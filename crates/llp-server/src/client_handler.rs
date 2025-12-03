//! Обработчик VPN клиента
//!
//! Этот модуль отвечает за:
//! - Чтение зашифрованных пакетов от клиента
//! - Дешифровку ChaCha20-Poly1305
//! - Извлечение IP пакетов
//! - Маршрутизацию через NAT gateway
//! - Отправку обратного трафика клиенту

use bytes::Bytes;
use llp_core::crypto::{AeadCipher, SessionKey, CHACHA20_NONCE_SIZE, POLY1305_TAG_SIZE};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

use crate::client_registry::ClientRegistry;
use crate::nat::NatGateway;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Обработчик клиента VPN
pub struct ClientHandler {
    session_id: u64,
    stream: TcpStream,
    session_key: SessionKey,
    nat_gateway: Option<Arc<RwLock<NatGateway>>>,
    client_registry: Arc<ClientRegistry>,
    send_counter: u64,
    receive_counter: u64,
    /// VPN IP адрес клиента
    vpn_ip: IpAddr,
}

impl ClientHandler {
    /// Создать новый обработчик
    pub fn new(
        session_id: u64,
        stream: TcpStream,
        session_key: SessionKey,
        nat_gateway: Option<Arc<RwLock<NatGateway>>>,
        client_registry: Arc<ClientRegistry>,
    ) -> Self {
        // Назначаем VPN IP на основе session_id
        // TODO: Использовать пул IP адресов для распределения
        let vpn_ip = IpAddr::V4(Ipv4Addr::new(
            10,
            8,
            0,
            // Простое распределение: 10.8.0.2 - 10.8.0.254
            (2 + (session_id % 253)) as u8,
        ));

        Self {
            session_id,
            stream,
            session_key,
            nat_gateway,
            client_registry,
            send_counter: 0,
            receive_counter: 0,
            vpn_ip,
        }
    }

    /// Запустить обработку клиента (основной цикл)
    pub async fn run(mut self) -> Result<()> {
        info!(
            "Запущен обработчик для клиента {} (VPN IP: {})",
            self.session_id, self.vpn_ip
        );

        // Создаём канал для получения пакетов от TUN
        let (tx, mut rx) = mpsc::unbounded_channel::<Bytes>();

        // Регистрируем клиента в реестре
        if let Err(e) = self.client_registry.register_client(self.vpn_ip, tx).await {
            error!(
                "Не удалось зарегистрировать клиента {} в реестре: {}",
                self.session_id, e
            );
            return Err(e);
        }

        info!(
            "Клиент {} зарегистрирован в реестре с IP {}",
            self.session_id, self.vpn_ip
        );

        // Создаём дешифратор
        let decrypt_cipher = AeadCipher::new(&self.session_key, self.session_id);

        // Разделяем stream на read/write половины
        let (mut read_half, mut write_half) = tokio::io::split(self.stream);

        // Spawn задачу для отправки пакетов клиенту (TUN -> Client)
        let session_key_clone = self.session_key.clone();
        let session_id = self.session_id;
        let send_task = tokio::spawn(async move {
            let mut send_counter = 0u64;
            let encrypt_cipher = AeadCipher::new(&session_key_clone, session_id);

            while let Some(ip_packet) = rx.recv().await {
                // Пропускаем счётчик до текущего
                let mut cipher = encrypt_cipher.clone();
                for _ in 0..send_counter {
                    let _ = cipher.encrypt(&[], &[]);
                }

                // Шифруем IP пакет
                let ciphertext_with_tag = match cipher.encrypt(&ip_packet, &[]) {
                    Ok(data) => data,
                    Err(e) => {
                        error!("Ошибка шифрования пакета для {}: {}", session_id, e);
                        continue;
                    }
                };

                // Строим nonce
                let mut nonce = [0u8; CHACHA20_NONCE_SIZE];
                nonce[0..8].copy_from_slice(&send_counter.to_le_bytes());
                nonce[8..12].copy_from_slice(&((session_id & 0xFFFFFFFF) as u32).to_le_bytes());

                // Формат: [length:u32][nonce:12][ciphertext+tag]
                let packet_len = (CHACHA20_NONCE_SIZE + ciphertext_with_tag.len()) as u32;

                // Отправляем пакет
                if let Err(e) = write_half.write_u32(packet_len).await {
                    error!("Ошибка отправки длины клиенту {}: {}", session_id, e);
                    break;
                }

                if let Err(e) = write_half.write_all(&nonce).await {
                    error!("Ошибка отправки nonce клиенту {}: {}", session_id, e);
                    break;
                }

                if let Err(e) = write_half.write_all(&ciphertext_with_tag).await {
                    error!("Ошибка отправки данных клиенту {}: {}", session_id, e);
                    break;
                }

                if let Err(e) = write_half.flush().await {
                    error!("Ошибка flush для клиента {}: {}", session_id, e);
                    break;
                }

                send_counter += 1;

                debug!(
                    "Отправлен пакет клиенту {}: {} байт",
                    session_id,
                    ip_packet.len()
                );
            }

            info!("Задача отправки для клиента {} завершена", session_id);
        });

        // Основной цикл чтения (Client -> TUN)
        let receive_counter = &mut self.receive_counter;
        let session_id = self.session_id;
        let nat_gateway = self.nat_gateway.clone();

        loop {
            // Читаем длину пакета (big-endian u32)
            let packet_len = match read_half.read_u32().await {
                Ok(len) => len as usize,
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::UnexpectedEof {
                        info!("Клиент {} отключился", session_id);
                        break;
                    }
                    error!("Ошибка чтения длины пакета от {}: {}", session_id, e);
                    break;
                }
            };

            // Проверка размера
            if packet_len == 0 || packet_len > 65536 {
                warn!(
                    "Недопустимый размер пакета от {}: {}",
                    session_id, packet_len
                );
                break;
            }

            // Читаем пакет: [nonce:12][ciphertext][tag:16]
            let mut packet_buf = vec![0u8; packet_len];
            if let Err(e) = read_half.read_exact(&mut packet_buf).await {
                error!("Ошибка чтения пакета от {}: {}", session_id, e);
                break;
            }

            // Проверяем минимальный размер (nonce + tag)
            if packet_buf.len() < CHACHA20_NONCE_SIZE + POLY1305_TAG_SIZE {
                warn!(
                    "Пакет от {} слишком маленький: {}",
                    session_id,
                    packet_buf.len()
                );
                continue;
            }

            // Извлекаем nonce
            let nonce = &packet_buf[0..CHACHA20_NONCE_SIZE];

            // Извлекаем counter из nonce (первые 8 байт, little-endian)
            let nonce_counter = u64::from_le_bytes(nonce[0..8].try_into().unwrap());

            // Проверка порядка пакетов (простая защита от replay)
            if nonce_counter < *receive_counter {
                warn!(
                    "Получен старый пакет от {} (counter: {}, expected: {})",
                    session_id, nonce_counter, receive_counter
                );
                continue;
            }
            *receive_counter = nonce_counter + 1;

            // Ciphertext + tag
            let ciphertext_with_tag = &packet_buf[CHACHA20_NONCE_SIZE..];

            // Дешифруем (без AAD для простоты)
            let plaintext = match decrypt_cipher.decrypt(ciphertext_with_tag, &[], nonce_counter) {
                Ok(data) => data,
                Err(e) => {
                    error!(
                        "Ошибка дешифровки пакета от {}: {}",
                        session_id, e
                    );
                    continue;
                }
            };

            debug!(
                "Получен пакет от {}: {} байт (расшифровано: {})",
                session_id,
                packet_buf.len(),
                plaintext.len()
            );

            // Обработка IP пакета
            if let Some(ref nat) = nat_gateway {
                let mut nat_lock = nat.write().await;
                if let Err(e) = nat_lock.route_packet(&plaintext, session_id).await {
                    error!("Ошибка маршрутизации пакета от {}: {}", session_id, e);
                }
            }
        }

        // Отменяем регистрацию клиента
        self.client_registry.unregister_client(self.vpn_ip).await;

        // Ожидаем завершения задачи отправки
        let _ = send_task.await;

        info!("Обработчик клиента {} завершён", session_id);
        Ok(())
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_version_parsing() {
        // IPv4 packet начинается с 0x45 (version 4, header length 5)
        let ipv4_packet = vec![0x45, 0x00, 0x00, 0x3c];
        let version = (ipv4_packet[0] >> 4) & 0x0F;
        assert_eq!(version, 4);

        // IPv6 packet начинается с 0x60 (version 6)
        let ipv6_packet = vec![0x60, 0x00, 0x00, 0x00];
        let version = (ipv6_packet[0] >> 4) & 0x0F;
        assert_eq!(version, 6);
    }
}
