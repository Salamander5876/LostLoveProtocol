//! TUN интерфейс для маршрутизации трафика
//!
//! Этот модуль отвечает за:
//! - Создание TUN интерфейса
//! - Чтение IP пакетов из TUN
//! - Запись IP пакетов в TUN
//! - Настройку IP адреса и маршрутов

use bytes::Bytes;
use std::net::IpAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, info, warn};
use tun::AsyncDevice;

use crate::config::ClientConfig;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// TUN интерфейс для VPN
pub struct TunInterface {
    /// TUN устройство
    device: AsyncDevice,
    /// Имя интерфейса
    name: String,
    /// IP адрес интерфейса
    ip_address: Option<IpAddr>,
    /// MTU
    mtu: u16,
}

impl TunInterface {
    /// Создать новый TUN интерфейс
    pub async fn create(config: &ClientConfig) -> Result<Self> {
        info!("Создание TUN интерфейса: {}", config.vpn.tun_name);

        // Конфигурация TUN устройства
        let mut tun_config = tun::Configuration::default();

        tun_config
            .name(&config.vpn.tun_name)
            .mtu(config.vpn.mtu as i32)
            .up();

        // Настройка IP адреса, если указан
        if let Some(ip) = config.vpn.client_ip {
            match ip {
                IpAddr::V4(ipv4) => {
                    tun_config.address(ipv4).netmask((255, 255, 255, 0));
                }
                IpAddr::V6(_) => {
                    warn!("IPv6 не поддерживается, используется IPv4");
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            tun_config.platform(|config| {
                config.packet_information(false);
            });
        }

        // Создание устройства
        let device = tun::create_as_async(&tun_config)?;
        let name = config.vpn.tun_name.clone();

        info!("✓ TUN интерфейс создан: {}", name);

        Ok(Self {
            device,
            name,
            ip_address: config.vpn.client_ip,
            mtu: config.vpn.mtu,
        })
    }

    /// Получить имя интерфейса
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Получить MTU
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Установить IP адрес интерфейса
    pub async fn set_ip_address(&mut self, ip: IpAddr) -> Result<()> {
        info!("Установка IP адреса {} для {}", ip, self.name);

        #[cfg(target_os = "linux")]
        {
            self.set_ip_linux(ip).await?;
        }

        #[cfg(target_os = "windows")]
        {
            self.set_ip_windows(ip).await?;
        }

        #[cfg(target_os = "macos")]
        {
            self.set_ip_macos(ip).await?;
        }

        self.ip_address = Some(ip);
        info!("✓ IP адрес установлен: {}", ip);

        Ok(())
    }

    /// Добавить маршрут по умолчанию через VPN
    pub async fn add_default_route(&self) -> Result<()> {
        info!("Добавление маршрута по умолчанию через {}", self.name);

        #[cfg(target_os = "linux")]
        {
            self.add_default_route_linux().await?;
        }

        #[cfg(target_os = "windows")]
        {
            self.add_default_route_windows().await?;
        }

        #[cfg(target_os = "macos")]
        {
            self.add_default_route_macos().await?;
        }

        info!("✓ Маршрут добавлен");
        Ok(())
    }

    /// Прочитать IP пакет из TUN
    pub async fn read_packet(&mut self) -> Result<Bytes> {
        let mut buf = vec![0u8; self.mtu as usize + 4]; // +4 для заголовка на некоторых платформах

        let len = self.device.read(&mut buf).await?;

        if len == 0 {
            return Err("TUN интерфейс закрыт".into());
        }

        debug!("TUN → Прочитан пакет: {} байт", len);

        Ok(Bytes::copy_from_slice(&buf[..len]))
    }

    /// Записать IP пакет в TUN
    pub async fn write_packet(&mut self, packet: &[u8]) -> Result<()> {
        if packet.is_empty() {
            return Ok(());
        }

        self.device.write_all(packet).await?;

        debug!("TUN ← Записан пакет: {} байт", packet.len());

        Ok(())
    }

    // Платформо-специфичные методы

    #[cfg(target_os = "linux")]
    async fn set_ip_linux(&self, ip: IpAddr) -> Result<()> {
        use std::process::Command;

        let ip_str = ip.to_string();

        // ip addr add <IP>/24 dev <name>
        let output = Command::new("ip")
            .args(&["addr", "add", &format!("{}/24", ip_str), "dev", &self.name])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("File exists") {
                return Err(format!("Ошибка установки IP: {}", stderr).into());
            }
        }

        // ip link set <name> up
        let output = Command::new("ip")
            .args(&["link", "set", &self.name, "up"])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Ошибка активации интерфейса: {}", stderr).into());
        }

        Ok(())
    }

    #[cfg(target_os = "linux")]
    async fn add_default_route_linux(&self) -> Result<()> {
        use std::process::Command;

        // ip route add default via <gateway> dev <name>
        if let Some(ip) = self.ip_address {
            let output = Command::new("ip")
                .args(&["route", "add", "default", "via", &ip.to_string(), "dev", &self.name])
                .output()?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                warn!("Не удалось добавить маршрут: {}", stderr);
            }
        }

        Ok(())
    }

    #[cfg(target_os = "windows")]
    async fn set_ip_windows(&self, ip: IpAddr) -> Result<()> {
        use std::process::Command;

        let ip_str = ip.to_string();

        // netsh interface ip set address <name> static <IP> 255.255.255.0
        let output = Command::new("netsh")
            .args(&[
                "interface",
                "ip",
                "set",
                "address",
                &self.name,
                "static",
                &ip_str,
                "255.255.255.0",
            ])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Ошибка установки IP: {}", stderr).into());
        }

        Ok(())
    }

    #[cfg(target_os = "windows")]
    async fn add_default_route_windows(&self) -> Result<()> {
        use std::process::Command;

        // route add 0.0.0.0 mask 0.0.0.0 <gateway>
        if let Some(ip) = self.ip_address {
            let output = Command::new("route")
                .args(&["add", "0.0.0.0", "mask", "0.0.0.0", &ip.to_string()])
                .output()?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                warn!("Не удалось добавить маршрут: {}", stderr);
            }
        }

        Ok(())
    }

    #[cfg(target_os = "macos")]
    async fn set_ip_macos(&self, ip: IpAddr) -> Result<()> {
        use std::process::Command;

        let ip_str = ip.to_string();

        // ifconfig <name> <IP> netmask 255.255.255.0 up
        let output = Command::new("ifconfig")
            .args(&[&self.name, &ip_str, "netmask", "255.255.255.0", "up"])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Ошибка установки IP: {}", stderr).into());
        }

        Ok(())
    }

    #[cfg(target_os = "macos")]
    async fn add_default_route_macos(&self) -> Result<()> {
        use std::process::Command;

        // route add default <gateway>
        if let Some(ip) = self.ip_address {
            let output = Command::new("route")
                .args(&["add", "default", &ip.to_string()])
                .output()?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                warn!("Не удалось добавить маршрут: {}", stderr);
            }
        }

        Ok(())
    }
}

impl Drop for TunInterface {
    fn drop(&mut self) {
        info!("Закрытие TUN интерфейса: {}", self.name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tun_interface_name() {
        // Тест создания интерфейса требует root прав, поэтому только проверяем структуру
        let config = ClientConfig::default();
        assert!(!config.vpn.tun_name.is_empty());
    }
}
