//! Обработчик VPN клиента
//!
//! Этот модуль отвечает за:
//! - Чтение зашифрованных пакетов от клиента
//! - Дешифровку ChaCha20-Poly1305
//! - Извлечение IP пакетов
//! - Маршрутизацию через NAT gateway

use bytes::{Bytes, BytesMut};
use llp_core::crypto::{AeadCipher, SessionKey, CHACHA20_NONCE_SIZE, POLY1305_TAG_SIZE};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::nat::NatGateway;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Обработчик клиента VPN
pub struct ClientHandler {
    session_id: u64,
    stream: TcpStream,
    session_key: SessionKey,
    nat_gateway: Option<Arc<RwLock<NatGateway>>>,
    send_counter: u64,
    receive_counter: u64,
}

impl ClientHandler {
    /// Создать новый обработчик
    pub fn new(
        session_id: u64,
        stream: TcpStream,
        session_key: SessionKey,
        nat_gateway: Option<Arc<RwLock<NatGateway>>>,
    ) -> Self {
        Self {
            session_id,
            stream,
            session_key,
            nat_gateway,
            send_counter: 0,
            receive_counter: 0,
        }
    }

    /// Запустить обработку клиента (основной цикл)
    pub async fn run(mut self) -> Result<()> {
        info!("Запущен обработчик для клиента {}", self.session_id);

        // Создаём дешифратор
        let mut decrypt_cipher = AeadCipher::new(&self.session_key, self.session_id);

        loop {
            // Читаем длину пакета (big-endian u32)
            let packet_len = match self.stream.read_u32().await {
                Ok(len) => len as usize,
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::UnexpectedEof {
                        info!("Клиент {} отключился", self.session_id);
                        break;
                    }
                    error!("Ошибка чтения длины пакета от {}: {}", self.session_id, e);
                    break;
                }
            };

            // Проверка размера
            if packet_len == 0 || packet_len > 65536 {
                warn!(
                    "Недопустимый размер пакета от {}: {}",
                    self.session_id, packet_len
                );
                break;
            }

            // Читаем пакет: [nonce:12][ciphertext][tag:16]
            let mut packet_buf = vec![0u8; packet_len];
            if let Err(e) = self.stream.read_exact(&mut packet_buf).await {
                error!("Ошибка чтения пакета от {}: {}", self.session_id, e);
                break;
            }

            // Проверяем минимальный размер (nonce + tag)
            if packet_buf.len() < CHACHA20_NONCE_SIZE + POLY1305_TAG_SIZE {
                warn!(
                    "Пакет от {} слишком маленький: {}",
                    self.session_id,
                    packet_buf.len()
                );
                continue;
            }

            // Извлекаем nonce
            let nonce = &packet_buf[0..CHACHA20_NONCE_SIZE];

            // Извлекаем counter из nonce (первые 8 байт, little-endian)
            let nonce_counter = u64::from_le_bytes(nonce[0..8].try_into().unwrap());

            // Проверка порядка пакетов (простая защита от replay)
            if nonce_counter < self.receive_counter {
                warn!(
                    "Получен старый пакет от {} (counter: {}, expected: {})",
                    self.session_id, nonce_counter, self.receive_counter
                );
                continue;
            }
            self.receive_counter = nonce_counter + 1;

            // Ciphertext + tag
            let ciphertext_with_tag = &packet_buf[CHACHA20_NONCE_SIZE..];

            // Дешифруем (без AAD для простоты)
            let plaintext = match decrypt_cipher.decrypt(ciphertext_with_tag, &[], nonce_counter) {
                Ok(data) => data,
                Err(e) => {
                    error!(
                        "Ошибка дешифровки пакета от {}: {}",
                        self.session_id, e
                    );
                    continue;
                }
            };

            debug!(
                "Получен пакет от {}: {} байт (расшифровано: {})",
                self.session_id,
                packet_buf.len(),
                plaintext.len()
            );

            // Обработка IP пакета
            if let Err(e) = self.process_ip_packet(&plaintext).await {
                error!(
                    "Ошибка обработки IP пакета от {}: {}",
                    self.session_id, e
                );
            }
        }

        info!("Обработчик клиента {} завершён", self.session_id);
        Ok(())
    }

    /// Обработать IP пакет
    async fn process_ip_packet(&mut self, ip_packet: &[u8]) -> Result<()> {
        if ip_packet.is_empty() {
            return Ok(());
        }

        // Проверяем версию IP (первые 4 бита)
        let version = (ip_packet[0] >> 4) & 0x0F;
        if version != 4 && version != 6 {
            warn!(
                "Неподдерживаемая версия IP от {}: {}",
                self.session_id, version
            );
            return Ok(());
        }

        debug!(
            "IP пакет от {}: IPv{}, {} байт",
            self.session_id,
            version,
            ip_packet.len()
        );

        // TODO: Отправить пакет через NAT gateway в интернет
        if let Some(nat) = &self.nat_gateway {
            let mut nat_lock = nat.write().await;
            if let Err(e) = nat_lock.route_packet(ip_packet, self.session_id).await {
                error!("Ошибка маршрутизации пакета: {}", e);
            }
        } else {
            warn!("NAT gateway не настроен, пакет отброшен");
        }

        Ok(())
    }

    /// Отправить IP пакет клиенту (для обратного трафика)
    #[allow(dead_code)]
    pub async fn send_ip_packet(&mut self, ip_packet: &[u8]) -> Result<()> {
        // Создаём шифровальщик
        let mut encrypt_cipher = AeadCipher::new(&self.session_key, self.session_id);

        // Пропускаем счётчик до текущего
        for _ in 0..self.send_counter {
            let _ = encrypt_cipher.encrypt(&[], &[]);
        }

        // Шифруем IP пакет
        let ciphertext_with_tag = encrypt_cipher.encrypt(ip_packet, &[])?;
        self.send_counter += 1;

        // Строим nonce
        let mut nonce = [0u8; CHACHA20_NONCE_SIZE];
        nonce[0..8].copy_from_slice(&self.send_counter.to_le_bytes());
        nonce[8..12].copy_from_slice(&((self.session_id & 0xFFFFFFFF) as u32).to_le_bytes());

        // Формат: [length:u32][nonce:12][ciphertext+tag]
        let packet_len = (CHACHA20_NONCE_SIZE + ciphertext_with_tag.len()) as u32;

        // Отправляем длину (big-endian)
        self.stream.write_u32(packet_len).await?;

        // Отправляем nonce
        self.stream.write_all(&nonce).await?;

        // Отправляем ciphertext + tag
        self.stream.write_all(&ciphertext_with_tag).await?;

        self.stream.flush().await?;

        debug!(
            "Отправлен IP пакет клиенту {}: {} байт",
            self.session_id,
            ip_packet.len()
        );

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
