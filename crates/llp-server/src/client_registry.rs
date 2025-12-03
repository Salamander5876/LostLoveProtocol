//! Client Registry для маршрутизации обратного трафика
//!
//! Этот модуль отвечает за:
//! - Регистрацию активных ClientHandler'ов
//! - Маппинг VPN IP -> канал для отправки пакетов
//! - Доставку пакетов из TUN интерфейса к клиентам

use bytes::Bytes;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, warn};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Реестр активных клиентов
pub struct ClientRegistry {
    /// Маппинг VPN IP адресов к каналам для отправки пакетов
    clients: Arc<RwLock<HashMap<IpAddr, mpsc::UnboundedSender<Bytes>>>>,
}

impl ClientRegistry {
    /// Создать новый реестр
    pub fn new() -> Self {
        Self {
            clients: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Зарегистрировать клиента с VPN IP адресом
    pub async fn register_client(
        &self,
        vpn_ip: IpAddr,
        tx: mpsc::UnboundedSender<Bytes>,
    ) -> Result<()> {
        let mut clients = self.clients.write().await;
        clients.insert(vpn_ip, tx);
        debug!("Клиент зарегистрирован: VPN IP = {}", vpn_ip);
        Ok(())
    }

    /// Отменить регистрацию клиента
    pub async fn unregister_client(&self, vpn_ip: IpAddr) {
        let mut clients = self.clients.write().await;
        clients.remove(&vpn_ip);
        debug!("Клиент удалён из реестра: VPN IP = {}", vpn_ip);
    }

    /// Отправить IP пакет клиенту по назначению
    pub async fn route_to_client(&self, packet: &[u8]) -> Result<()> {
        // Извлекаем destination IP из пакета
        let dst_ip = match extract_dst_ip(packet) {
            Some(ip) => ip,
            None => {
                warn!("Не удалось извлечь destination IP из пакета");
                return Ok(());
            }
        };

        // Находим канал клиента
        let clients = self.clients.read().await;
        if let Some(tx) = clients.get(&dst_ip) {
            let packet_bytes = Bytes::copy_from_slice(packet);
            if let Err(e) = tx.send(packet_bytes) {
                warn!("Не удалось отправить пакет клиенту {}: {}", dst_ip, e);
            } else {
                debug!("Пакет отправлен клиенту {} ({} байт)", dst_ip, packet.len());
            }
        } else {
            debug!("Клиент с IP {} не найден в реестре", dst_ip);
        }

        Ok(())
    }

    /// Получить количество активных клиентов
    pub async fn active_count(&self) -> usize {
        let clients = self.clients.read().await;
        clients.len()
    }
}

impl Default for ClientRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Извлечь destination IP из IPv4/IPv6 пакета
fn extract_dst_ip(packet: &[u8]) -> Option<IpAddr> {
    if packet.len() < 20 {
        return None;
    }

    // Проверяем версию IP
    let version = (packet[0] >> 4) & 0x0F;

    match version {
        4 => {
            // IPv4: байты 16-19 = destination IP
            if packet.len() < 20 {
                return None;
            }
            let dst_bytes = &packet[16..20];
            Some(IpAddr::V4(std::net::Ipv4Addr::new(
                dst_bytes[0],
                dst_bytes[1],
                dst_bytes[2],
                dst_bytes[3],
            )))
        }
        6 => {
            // IPv6: байты 24-39 = destination IP
            if packet.len() < 40 {
                return None;
            }
            let dst_bytes: [u8; 16] = packet[24..40].try_into().ok()?;
            Some(IpAddr::V6(std::net::Ipv6Addr::from(dst_bytes)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_dst_ip_v4() {
        // Минимальный IPv4 пакет с destination IP 10.8.0.2
        let packet = vec![
            0x45, 0x00, 0x00, 0x14, // Version, IHL, TOS, Length
            0x00, 0x00, 0x00, 0x00, // ID, Flags, Fragment
            0x40, 0x00, 0x00, 0x00, // TTL, Protocol, Checksum
            192, 168, 1, 1,         // Source IP
            10, 8, 0, 2,            // Destination IP
        ];

        let dst_ip = extract_dst_ip(&packet).unwrap();
        assert_eq!(
            dst_ip,
            IpAddr::V4(std::net::Ipv4Addr::new(10, 8, 0, 2))
        );
    }

    #[tokio::test]
    async fn test_client_registry() {
        let registry = ClientRegistry::new();
        let vpn_ip = IpAddr::V4(std::net::Ipv4Addr::new(10, 8, 0, 2));

        let (tx, _rx) = mpsc::unbounded_channel();
        registry.register_client(vpn_ip, tx).await.unwrap();

        assert_eq!(registry.active_count().await, 1);

        registry.unregister_client(vpn_ip).await;
        assert_eq!(registry.active_count().await, 0);
    }
}
