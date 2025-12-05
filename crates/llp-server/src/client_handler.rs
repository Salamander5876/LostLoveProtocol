//! Обработчик VPN клиента
//!
//! Этот модуль отвечает за:
//! - Чтение зашифрованных UDP пакетов от клиента
//! - Дешифровку ChaCha20-Poly1305
//! - Извлечение IP пакетов
//! - Маршрутизацию через NAT gateway
//! - Отправку обратного трафика клиенту

use bytes::Bytes;
use llp_core::crypto::{AeadCipher, SessionKey, CHACHA20_NONCE_SIZE, POLY1305_TAG_SIZE};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

use crate::client_registry::ClientRegistry;
use crate::nat::NatGateway;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Обработчик клиента VPN (UDP версия)
pub struct ClientHandler {
    session_id: u64,
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    session_key: SessionKey,
    nat_gateway: Option<Arc<RwLock<NatGateway>>>,
    client_registry: Arc<ClientRegistry>,
    send_counter: u64,
    receive_counter: u64,
    /// VPN IP адрес клиента
    vpn_ip: IpAddr,
}

impl ClientHandler {
    /// Создать новый обработчик для UDP
    pub fn new_udp(
        session_id: u64,
        socket: Arc<UdpSocket>,
        peer_addr: SocketAddr,
        session_key: SessionKey,
        nat_gateway: Option<Arc<RwLock<NatGateway>>>,
        client_registry: Arc<ClientRegistry>,
    ) -> Self {
        // Назначаем VPN IP на основе session_id
        let vpn_ip = IpAddr::V4(Ipv4Addr::new(
            10,
            8,
            0,
            // Простое распределение: 10.8.0.2 - 10.8.0.254
            (2 + (session_id % 253)) as u8,
        ));

        Self {
            session_id,
            socket,
            peer_addr,
            session_key,
            nat_gateway,
            client_registry,
            send_counter: 0,
            receive_counter: 0,
            vpn_ip,
        }
    }

    /// Запустить обработку клиента (основной цикл)
    pub async fn run(self) -> Result<()> {
        info!(
            "Запущен обработчик для клиента {} (VPN IP: {}, peer: {})",
            self.session_id, self.vpn_ip, self.peer_addr
        );

        // Создаём канал для получения пакетов от TUN (обратный трафик)
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

        // Note: дешифратор будет создаваться в handle_incoming_packet

        // Spawn задачу для отправки пакетов клиенту (TUN -> Client)
        let socket_clone = Arc::clone(&self.socket);
        let peer_addr = self.peer_addr;
        let session_key_clone = self.session_key.clone();
        let session_id = self.session_id;

        let send_task = tokio::spawn(async move {
            let mut send_counter = 0u64;

            while let Some(ip_packet) = rx.recv().await {
                // Создаём новый шифратор для каждого пакета
                let mut encrypt_cipher = AeadCipher::new(&session_key_clone, session_id);

                // Пропускаем счётчик до текущего
                for _ in 0..send_counter {
                    let _ = encrypt_cipher.encrypt(&[], &[]);
                }

                // Шифруем IP пакет
                let ciphertext_with_tag = match encrypt_cipher.encrypt(&ip_packet, &[]) {
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

                // Формат UDP пакета: [nonce:12][ciphertext+tag]
                let mut udp_packet = Vec::with_capacity(CHACHA20_NONCE_SIZE + ciphertext_with_tag.len());
                udp_packet.extend_from_slice(&nonce);
                udp_packet.extend_from_slice(&ciphertext_with_tag);

                // Отправляем пакет
                if let Err(e) = socket_clone.send_to(&udp_packet, peer_addr).await {
                    error!("Ошибка отправки UDP пакета клиенту {}: {}", session_id, e);
                    break;
                }

                send_counter += 1;

                debug!(
                    "Отправлен UDP пакет клиенту {} ({}): {} байт IP данных",
                    session_id, peer_addr, ip_packet.len()
                );
            }

            info!("Задача отправки для клиента {} завершена", session_id);
        });

        // Основной цикл чтения UDP пакетов (Client -> TUN)
        // ВАЖНО: В UDP модели каждый клиент не имеет отдельного цикла чтения,
        // пакеты обрабатываются в главном listener loop.
        // Здесь мы просто ждём завершения задачи отправки.

        info!(
            "Обработчик клиента {} готов (пакеты обрабатываются в listener)",
            session_id
        );

        // Ожидаем завершения задачи отправки
        let _ = send_task.await;

        // Отменяем регистрацию клиента
        self.client_registry.unregister_client(self.vpn_ip).await;

        info!("Обработчик клиента {} завершён", session_id);
        Ok(())
    }

    /// Обработка входящего VPN пакета от клиента (вызывается из listener)
    pub async fn handle_incoming_packet(
        session_id: u64,
        packet: &[u8],
        decrypt_cipher: &AeadCipher,
        nat_gateway: &Option<Arc<RwLock<NatGateway>>>,
        receive_counter: &mut u64,
        client_registry: &Arc<ClientRegistry>,
        vpn_ip: IpAddr,
    ) -> Result<()> {
        // Проверяем минимальный размер (nonce + tag)
        if packet.len() < CHACHA20_NONCE_SIZE + POLY1305_TAG_SIZE {
            warn!(
                "Пакет от {} слишком маленький: {}",
                session_id,
                packet.len()
            );
            return Ok(());
        }

        // Извлекаем nonce
        let nonce = &packet[0..CHACHA20_NONCE_SIZE];

        // Извлекаем counter из nonce (первые 8 байт, little-endian)
        let nonce_counter = u64::from_le_bytes(nonce[0..8].try_into().unwrap());

        // Проверка порядка пакетов (простая защита от replay)
        if nonce_counter < *receive_counter {
            warn!(
                "Получен старый пакет от {} (counter: {}, expected: {})",
                session_id, nonce_counter, receive_counter
            );
            return Ok(());
        }
        *receive_counter = nonce_counter + 1;

        // Ciphertext + tag
        let ciphertext_with_tag = &packet[CHACHA20_NONCE_SIZE..];

        // Дешифруем
        let plaintext = match decrypt_cipher.decrypt(ciphertext_with_tag, &[], nonce_counter) {
            Ok(data) => data,
            Err(e) => {
                error!("Ошибка дешифровки пакета от {}: {}", session_id, e);
                return Ok(());
            }
        };

        debug!(
            "Получен UDP пакет от {}: {} байт (расшифровано: {})",
            session_id,
            packet.len(),
            plaintext.len()
        );

        // TODO: Временное эхо для тестирования - убрать после настройки NAT
        // Просто отправляем полученный IP пакет обратно клиенту
        debug!("ECHO TEST: Отправка пакета обратно клиенту {} (эхо-тест)", vpn_ip);

        // Прямая отправка через реестр (без извлечения dst_ip)
        let clients = client_registry.clients.read().await;
        if let Some(tx) = clients.get(&vpn_ip) {
            let packet_bytes = Bytes::copy_from_slice(&plaintext);
            if let Err(e) = tx.send(packet_bytes) {
                error!("Ошибка отправки эхо-пакета клиенту {}: {}", session_id, e);
            } else {
                debug!("ECHO TEST: Пакет успешно отправлен клиенту {} ({} байт)", vpn_ip, plaintext.len());
            }
        } else {
            debug!("ECHO TEST: Клиент {} не найден в реестре", vpn_ip);
        }

        // Обработка IP пакета через NAT
        if let Some(ref nat) = nat_gateway {
            let mut nat_lock = nat.write().await;
            if let Err(e) = nat_lock.route_packet(&plaintext, session_id).await {
                error!("Ошибка маршрутизации пакета от {}: {}", session_id, e);
            }
        }

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
