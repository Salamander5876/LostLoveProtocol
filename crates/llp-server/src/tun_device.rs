//! TUN device на сервере для маршрутизации VPN трафика
//!
//! Этот модуль создаёт TUN interface, через который пакеты от клиентов
//! отправляются в интернет через NAT

use std::io::{Read, Write};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// TUN device для VPN сервера
pub struct ServerTunDevice {
    iface: Option<tun_tap::Iface>,
    name: String,
}

impl ServerTunDevice {
    /// Создать новый TUN device
    pub fn new(name: String) -> Result<Self> {
        let iface = tun_tap::Iface::without_packet_info(&name, tun_tap::Mode::Tun)
            .map_err(|e| format!("Не удалось создать TUN interface: {}", e))?;

        info!("TUN interface создан: {}", name);

        Ok(Self {
            iface: Some(iface),
            name,
        })
    }

    /// Настроить IP адрес интерфейса
    pub fn configure_ip(&self, ip: &str, netmask: &str) -> Result<()> {
        use std::process::Command;

        // ip addr add 10.8.0.1/24 dev llp0
        let output = Command::new("ip")
            .args(&["addr", "add", &format!("{}/{}", ip, Self::netmask_to_cidr(netmask)), "dev", &self.name])
            .output()?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            if !err.contains("exists") {
                return Err(format!("Ошибка настройки IP: {}", err).into());
            }
        }

        // ip link set llp0 up
        let output = Command::new("ip")
            .args(&["link", "set", &self.name, "up"])
            .output()?;

        if !output.status.success() {
            return Err(format!(
                "Ошибка активации интерфейса: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }

        info!("TUN interface {} настроен: {}/{}", self.name, ip, Self::netmask_to_cidr(netmask));

        Ok(())
    }

    /// Конвертировать netmask в CIDR префикс
    fn netmask_to_cidr(netmask: &str) -> u8 {
        match netmask {
            "255.255.255.0" => 24,
            "255.255.0.0" => 16,
            "255.0.0.0" => 8,
            _ => 24, // default
        }
    }

    /// Записать IP пакет в TUN interface (отправить в интернет)
    pub fn write_packet(&mut self, packet: &[u8]) -> Result<usize> {
        if let Some(ref mut iface) = self.iface {
            iface
                .write(packet)
                .map_err(|e| format!("Ошибка записи в TUN: {}", e).into())
        } else {
            Err("TUN interface не инициализирован".into())
        }
    }

    /// Прочитать IP пакет из TUN interface (из интернета)
    pub fn read_packet(&mut self, buffer: &mut [u8]) -> Result<usize> {
        if let Some(ref mut iface) = self.iface {
            iface
                .read(buffer)
                .map_err(|e| format!("Ошибка чтения из TUN: {}", e).into())
        } else {
            Err("TUN interface не инициализирован".into())
        }
    }

    /// Получить имя интерфейса
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Drop for ServerTunDevice {
    fn drop(&mut self) {
        info!("Закрытие TUN interface: {}", self.name);
    }
}

/// Глобальный TUN device для сервера (синглтон)
pub type SharedTunDevice = Arc<RwLock<ServerTunDevice>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netmask_conversion() {
        assert_eq!(ServerTunDevice::netmask_to_cidr("255.255.255.0"), 24);
        assert_eq!(ServerTunDevice::netmask_to_cidr("255.255.0.0"), 16);
        assert_eq!(ServerTunDevice::netmask_to_cidr("255.0.0.0"), 8);
    }
}
