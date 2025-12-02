//! Конфигурация сервера LLP
//!
//! Этот модуль отвечает за загрузку и валидацию конфигурации сервера.

use llp_core::packet::MimicryProfile;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;

/// Конфигурация сервера LLP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Сетевые настройки
    pub network: NetworkConfig,

    /// Настройки VPN
    pub vpn: VpnConfig,

    /// Настройки безопасности
    pub security: SecurityConfig,

    /// Настройки логирования
    pub logging: LoggingConfig,
}

/// Сетевые настройки
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// IP адрес для прослушивания (0.0.0.0 для всех интерфейсов)
    #[serde(default = "default_bind_ip")]
    pub bind_ip: IpAddr,

    /// Порт для прослушивания
    #[serde(default = "default_bind_port")]
    pub port: u16,

    /// Максимальное количество одновременных подключений
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,

    /// Таймаут для установления соединения (секунды)
    #[serde(default = "default_connection_timeout")]
    pub connection_timeout_secs: u64,
}

/// Настройки VPN
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnConfig {
    /// Подсеть для VPN клиентов (например, 10.8.0.0/24)
    #[serde(default = "default_vpn_subnet")]
    pub subnet: String,

    /// IP адрес сервера в VPN подсети
    #[serde(default = "default_vpn_server_ip")]
    pub server_ip: IpAddr,

    /// DNS серверы для клиентов
    #[serde(default = "default_dns_servers")]
    pub dns_servers: Vec<IpAddr>,

    /// MTU для VPN интерфейса
    #[serde(default = "default_mtu")]
    pub mtu: u16,
}

/// Настройки безопасности
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Профиль мимикрии по умолчанию
    #[serde(default = "default_mimicry_profile")]
    pub default_mimicry_profile: String,

    /// Время жизни сессии (секунды)
    #[serde(default = "default_session_lifetime")]
    pub session_lifetime_secs: u64,

    /// Интервал keepalive (секунды)
    #[serde(default = "default_keepalive_interval")]
    pub keepalive_interval_secs: u64,

    /// Таймаут keepalive (секунды)
    #[serde(default = "default_keepalive_timeout")]
    pub keepalive_timeout_secs: u64,

    /// Максимальный drift времени (секунды)
    #[serde(default = "default_max_timestamp_drift")]
    pub max_timestamp_drift_secs: u64,
}

/// Настройки логирования
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Уровень логирования (trace, debug, info, warn, error)
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Логировать в файл
    #[serde(default = "default_log_to_file")]
    pub log_to_file: bool,

    /// Путь к файлу логов
    #[serde(default = "default_log_file_path")]
    pub log_file_path: String,
}

// Значения по умолчанию
fn default_bind_ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))
}

fn default_bind_port() -> u16 {
    8443
}

fn default_max_connections() -> usize {
    1000
}

fn default_connection_timeout() -> u64 {
    30
}

fn default_vpn_subnet() -> String {
    "10.8.0.0/24".to_string()
}

fn default_vpn_server_ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1))
}

fn default_dns_servers() -> Vec<IpAddr> {
    vec![
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),      // Google DNS
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),      // Cloudflare DNS
    ]
}

fn default_mtu() -> u16 {
    1420
}

fn default_mimicry_profile() -> String {
    "vk_video".to_string()
}

fn default_session_lifetime() -> u64 {
    24 * 60 * 60 // 24 часа
}

fn default_keepalive_interval() -> u64 {
    30
}

fn default_keepalive_timeout() -> u64 {
    90
}

fn default_max_timestamp_drift() -> u64 {
    5 * 60 // 5 минут
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_to_file() -> bool {
    true
}

fn default_log_file_path() -> String {
    "/var/log/llp-server.log".to_string()
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            network: NetworkConfig::default(),
            vpn: VpnConfig::default(),
            security: SecurityConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            bind_ip: default_bind_ip(),
            port: default_bind_port(),
            max_connections: default_max_connections(),
            connection_timeout_secs: default_connection_timeout(),
        }
    }
}

impl Default for VpnConfig {
    fn default() -> Self {
        Self {
            subnet: default_vpn_subnet(),
            server_ip: default_vpn_server_ip(),
            dns_servers: default_dns_servers(),
            mtu: default_mtu(),
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            default_mimicry_profile: default_mimicry_profile(),
            session_lifetime_secs: default_session_lifetime(),
            keepalive_interval_secs: default_keepalive_interval(),
            keepalive_timeout_secs: default_keepalive_timeout(),
            max_timestamp_drift_secs: default_max_timestamp_drift(),
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            log_to_file: default_log_to_file(),
            log_file_path: default_log_file_path(),
        }
    }
}

impl ServerConfig {
    /// Загрузить конфигурацию из TOML файла
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, anyhow::Error> {
        let content = std::fs::read_to_string(path)?;
        let config: ServerConfig = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    /// Сохранить конфигурацию в TOML файл
    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), anyhow::Error> {
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Валидация конфигурации
    pub fn validate(&self) -> Result<(), anyhow::Error> {
        // Проверка порта
        if self.network.port == 0 {
            anyhow::bail!("Порт не может быть 0");
        }

        // Проверка max_connections
        if self.network.max_connections == 0 {
            anyhow::bail!("max_connections должен быть > 0");
        }

        // Проверка профиля мимикрии
        self.parse_mimicry_profile()?;

        // Проверка MTU
        if self.vpn.mtu < 576 || self.vpn.mtu > 9000 {
            anyhow::bail!("MTU должен быть в диапазоне 576-9000");
        }

        Ok(())
    }

    /// Получить SocketAddr для прослушивания
    pub fn bind_address(&self) -> SocketAddr {
        SocketAddr::new(self.network.bind_ip, self.network.port)
    }

    /// Парсинг профиля мимикрии из строки
    pub fn parse_mimicry_profile(&self) -> Result<MimicryProfile, anyhow::Error> {
        match self.security.default_mimicry_profile.as_str() {
            "none" => Ok(MimicryProfile::None),
            "vk_video" => Ok(MimicryProfile::VkVideo),
            "yandex_music" => Ok(MimicryProfile::YandexMusic),
            "rutube" => Ok(MimicryProfile::RuTube),
            unknown => anyhow::bail!("Неизвестный профиль мимикрии: {}", unknown),
        }
    }

    /// Получить таймаут подключения
    pub fn connection_timeout(&self) -> Duration {
        Duration::from_secs(self.network.connection_timeout_secs)
    }

    /// Получить время жизни сессии
    pub fn session_lifetime(&self) -> Duration {
        Duration::from_secs(self.security.session_lifetime_secs)
    }

    /// Получить интервал keepalive
    #[allow(dead_code)]
    pub fn keepalive_interval(&self) -> Duration {
        Duration::from_secs(self.security.keepalive_interval_secs)
    }

    /// Получить таймаут keepalive
    #[allow(dead_code)]
    pub fn keepalive_timeout(&self) -> Duration {
        Duration::from_secs(self.security.keepalive_timeout_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ServerConfig::default();
        assert_eq!(config.network.port, 8443);
        assert_eq!(config.network.max_connections, 1000);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_parse_mimicry_profile() {
        let mut config = ServerConfig::default();

        config.security.default_mimicry_profile = "vk_video".to_string();
        assert!(matches!(
            config.parse_mimicry_profile().unwrap(),
            MimicryProfile::VkVideo
        ));

        config.security.default_mimicry_profile = "yandex_music".to_string();
        assert!(matches!(
            config.parse_mimicry_profile().unwrap(),
            MimicryProfile::YandexMusic
        ));

        config.security.default_mimicry_profile = "unknown".to_string();
        assert!(config.parse_mimicry_profile().is_err());
    }

    #[test]
    fn test_bind_address() {
        let config = ServerConfig::default();
        let addr = config.bind_address();
        assert_eq!(addr.port(), 8443);
    }

    #[test]
    fn test_validation() {
        let mut config = ServerConfig::default();

        // Валидная конфигурация
        assert!(config.validate().is_ok());

        // Невалидный порт
        config.network.port = 0;
        assert!(config.validate().is_err());
        config.network.port = 8443;

        // Невалидный max_connections
        config.network.max_connections = 0;
        assert!(config.validate().is_err());
        config.network.max_connections = 1000;

        // Невалидный MTU
        config.vpn.mtu = 100;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_toml_serialization() {
        let config = ServerConfig::default();
        let toml_str = toml::to_string(&config).unwrap();
        assert!(toml_str.contains("bind_ip"));
        assert!(toml_str.contains("port"));

        let deserialized: ServerConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(config.network.port, deserialized.network.port);
    }
}
