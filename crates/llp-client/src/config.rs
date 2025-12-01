//! Конфигурация клиента LLP
//!
//! Этот модуль отвечает за загрузку и валидацию конфигурации клиента.

use llp_core::packet::MimicryProfile;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::time::Duration;

/// Конфигурация клиента LLP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Настройки сервера
    pub server: ServerConfig,

    /// Настройки VPN
    pub vpn: VpnConfig,

    /// Настройки безопасности
    pub security: SecurityConfig,

    /// Настройки логирования
    pub logging: LoggingConfig,
}

/// Настройки сервера
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// IP адрес или hostname сервера
    pub host: String,

    /// Порт сервера
    #[serde(default = "default_server_port")]
    pub port: u16,

    /// Таймаут подключения (секунды)
    #[serde(default = "default_connection_timeout")]
    pub connection_timeout_secs: u64,

    /// Попытки переподключения
    #[serde(default = "default_reconnect_attempts")]
    pub reconnect_attempts: u32,

    /// Задержка между попытками переподключения (секунды)
    #[serde(default = "default_reconnect_delay")]
    pub reconnect_delay_secs: u64,
}

/// Настройки VPN
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnConfig {
    /// IP адрес клиента в VPN (назначается сервером, если не указан)
    pub client_ip: Option<IpAddr>,

    /// DNS серверы
    #[serde(default = "default_dns_servers")]
    pub dns_servers: Vec<IpAddr>,

    /// MTU для TUN интерфейса
    #[serde(default = "default_mtu")]
    pub mtu: u16,

    /// Имя TUN интерфейса
    #[serde(default = "default_tun_name")]
    pub tun_name: String,

    /// Маршрутизировать весь трафик через VPN
    #[serde(default = "default_route_all")]
    pub route_all_traffic: bool,
}

/// Настройки безопасности
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Профиль мимикрии
    #[serde(default = "default_mimicry_profile")]
    pub mimicry_profile: String,

    /// Интервал keepalive (секунды)
    #[serde(default = "default_keepalive_interval")]
    pub keepalive_interval_secs: u64,

    /// Верификация сертификата сервера
    #[serde(default = "default_verify_server")]
    pub verify_server: bool,
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
fn default_server_port() -> u16 {
    8443
}

fn default_connection_timeout() -> u64 {
    30
}

fn default_reconnect_attempts() -> u32 {
    5
}

fn default_reconnect_delay() -> u64 {
    5
}

fn default_dns_servers() -> Vec<IpAddr> {
    vec![
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
    ]
}

fn default_mtu() -> u16 {
    1420
}

fn default_tun_name() -> String {
    #[cfg(windows)]
    {
        "llp0".to_string()
    }
    #[cfg(unix)]
    {
        "tun0".to_string()
    }
}

fn default_route_all() -> bool {
    true
}

fn default_mimicry_profile() -> String {
    "vk_video".to_string()
}

fn default_keepalive_interval() -> u64 {
    30
}

fn default_verify_server() -> bool {
    true
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_to_file() -> bool {
    false
}

fn default_log_file_path() -> String {
    #[cfg(windows)]
    {
        "C:\\ProgramData\\llp-client\\llp-client.log".to_string()
    }
    #[cfg(unix)]
    {
        "/var/log/llp-client.log".to_string()
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            vpn: VpnConfig::default(),
            security: SecurityConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: default_server_port(),
            connection_timeout_secs: default_connection_timeout(),
            reconnect_attempts: default_reconnect_attempts(),
            reconnect_delay_secs: default_reconnect_delay(),
        }
    }
}

impl Default for VpnConfig {
    fn default() -> Self {
        Self {
            client_ip: None,
            dns_servers: default_dns_servers(),
            mtu: default_mtu(),
            tun_name: default_tun_name(),
            route_all_traffic: default_route_all(),
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            mimicry_profile: default_mimicry_profile(),
            keepalive_interval_secs: default_keepalive_interval(),
            verify_server: default_verify_server(),
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

impl ClientConfig {
    /// Загрузить конфигурацию из TOML файла
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, anyhow::Error> {
        let content = std::fs::read_to_string(path)?;
        let config: ClientConfig = toml::from_str(&content)?;
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
        // Проверка хоста
        if self.server.host.is_empty() {
            anyhow::bail!("Адрес сервера не может быть пустым");
        }

        // Проверка порта
        if self.server.port == 0 {
            anyhow::bail!("Порт сервера не может быть 0");
        }

        // Проверка профиля мимикрии
        self.parse_mimicry_profile()?;

        // Проверка MTU
        if self.vpn.mtu < 576 || self.vpn.mtu > 9000 {
            anyhow::bail!("MTU должен быть в диапазоне 576-9000");
        }

        Ok(())
    }

    /// Получить адрес сервера
    pub fn server_address(&self) -> String {
        format!("{}:{}", self.server.host, self.server.port)
    }

    /// Парсинг профиля мимикрии из строки
    pub fn parse_mimicry_profile(&self) -> Result<MimicryProfile, anyhow::Error> {
        match self.security.mimicry_profile.as_str() {
            "none" => Ok(MimicryProfile::None),
            "vk_video" => Ok(MimicryProfile::VkVideo),
            "yandex_music" => Ok(MimicryProfile::YandexMusic),
            "rutube" => Ok(MimicryProfile::RuTube),
            unknown => anyhow::bail!("Неизвестный профиль мимикрии: {}", unknown),
        }
    }

    /// Получить таймаут подключения
    pub fn connection_timeout(&self) -> Duration {
        Duration::from_secs(self.server.connection_timeout_secs)
    }

    /// Получить интервал keepalive
    pub fn keepalive_interval(&self) -> Duration {
        Duration::from_secs(self.security.keepalive_interval_secs)
    }

    /// Получить задержку переподключения
    pub fn reconnect_delay(&self) -> Duration {
        Duration::from_secs(self.server.reconnect_delay_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ClientConfig::default();
        assert_eq!(config.server.port, 8443);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_parse_mimicry_profile() {
        let mut config = ClientConfig::default();

        config.security.mimicry_profile = "vk_video".to_string();
        assert!(matches!(
            config.parse_mimicry_profile().unwrap(),
            MimicryProfile::VkVideo
        ));

        config.security.mimicry_profile = "unknown".to_string();
        assert!(config.parse_mimicry_profile().is_err());
    }

    #[test]
    fn test_server_address() {
        let mut config = ClientConfig::default();
        config.server.host = "example.com".to_string();
        config.server.port = 9000;

        assert_eq!(config.server_address(), "example.com:9000");
    }

    #[test]
    fn test_validation() {
        let mut config = ClientConfig::default();

        // Валидная конфигурация
        assert!(config.validate().is_ok());

        // Пустой хост
        config.server.host = String::new();
        assert!(config.validate().is_err());
        config.server.host = "localhost".to_string();

        // Невалидный порт
        config.server.port = 0;
        assert!(config.validate().is_err());
        config.server.port = 8443;

        // Невалидный MTU
        config.vpn.mtu = 100;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_toml_serialization() {
        let config = ClientConfig::default();
        let toml_str = toml::to_string(&config).unwrap();
        assert!(toml_str.contains("host"));
        assert!(toml_str.contains("port"));

        let deserialized: ClientConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(config.server.port, deserialized.server.port);
    }
}
