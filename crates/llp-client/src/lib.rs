//! # LLP Client Library
//!
//! Клиентская библиотека для LostLoveProtocol VPN.
//!
//! Предоставляет API для:
//! - Подключения к серверу
//! - Управления TUN интерфейсом
//! - Маршрутизации трафика

pub mod config;
pub mod connection;
pub mod tunnel;

pub use config::ClientConfig;
pub use connection::{ConnectionInfo, ConnectionState, ServerConnection};
pub use tunnel::TunInterface;

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// VPN клиент
pub struct VpnClient {
    /// Конфигурация
    config: Arc<ClientConfig>,
    /// Подключение к серверу
    connection: Arc<RwLock<ServerConnection>>,
    /// TUN интерфейс
    tunnel: Option<TunInterface>,
}

impl VpnClient {
    /// Создать нового клиента
    pub fn new(config: ClientConfig) -> Self {
        let config = Arc::new(config);
        let connection = Arc::new(RwLock::new(ServerConnection::new(Arc::clone(&config))));

        Self {
            config,
            connection,
            tunnel: None,
        }
    }

    /// Подключиться к серверу и запустить VPN
    pub async fn connect(&mut self) -> Result<()> {
        info!("Запуск VPN клиента...");

        // Создание TUN интерфейса
        let mut tunnel = TunInterface::create(&self.config).await?;

        // Подключение к серверу
        {
            let mut conn = self.connection.write().await;
            conn.connect().await?;
        }

        // Настройка IP адреса (если назначен сервером или из конфигурации)
        if let Some(ip) = self.config.vpn.client_ip {
            tunnel.set_ip_address(ip).await?;
        }

        // Добавление маршрута по умолчанию
        if self.config.vpn.route_all_traffic {
            tunnel.add_default_route().await?;
        }

        self.tunnel = Some(tunnel);

        info!("✓ VPN клиент запущен");

        Ok(())
    }

    /// Запустить основной цикл маршрутизации
    pub async fn run(&mut self) -> Result<()> {
        let tunnel = self.tunnel.as_mut().ok_or("TUN интерфейс не создан")?;

        info!("Запуск цикла маршрутизации...");

        let connection = Arc::clone(&self.connection);
        let keepalive_interval = self.config.keepalive_interval();

        // Задача для keepalive
        let conn_keepalive = Arc::clone(&connection);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(keepalive_interval);
            loop {
                interval.tick().await;
                let mut conn = conn_keepalive.write().await;
                if conn.is_connected().await {
                    if let Err(e) = conn.send_keepalive().await {
                        error!("Ошибка отправки keepalive: {}", e);
                    }
                }
            }
        });

        // Основной цикл
        loop {
            tokio::select! {
                // Чтение из TUN → отправка на сервер
                result = tunnel.read_packet() => {
                    match result {
                        Ok(packet) => {
                            let mut conn = connection.write().await;
                            if let Err(e) = conn.send_packet(&packet).await {
                                error!("Ошибка отправки пакета: {}", e);

                                // Попытка переподключения
                                if let Err(e) = conn.reconnect().await {
                                    error!("Не удалось переподключиться: {}", e);
                                    return Err(e);
                                }
                            }
                        }
                        Err(e) => {
                            error!("Ошибка чтения из TUN: {}", e);
                            return Err(e);
                        }
                    }
                }

                // Получение от сервера → запись в TUN
                result = async {
                    let mut conn = connection.write().await;
                    conn.receive_packet().await
                } => {
                    match result {
                        Ok(packet) => {
                            if let Err(e) = tunnel.write_packet(&packet).await {
                                error!("Ошибка записи в TUN: {}", e);
                            }
                        }
                        Err(e) => {
                            error!("Ошибка получения пакета: {}", e);

                            // Попытка переподключения
                            let mut conn = connection.write().await;
                            if let Err(e) = conn.reconnect().await {
                                error!("Не удалось переподключиться: {}", e);
                                return Err(e);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Получить информацию о подключении
    pub fn connection_info(&self) -> Arc<RwLock<ConnectionInfo>> {
        let conn_lock = self.connection.blocking_read();
        conn_lock.info()
    }

    /// Отключиться
    pub async fn disconnect(&mut self) -> Result<()> {
        info!("Отключение от VPN...");

        self.tunnel = None;
        self.connection = Arc::new(RwLock::new(ServerConnection::new(Arc::clone(
            &self.config,
        ))));

        info!("✓ Отключено");

        Ok(())
    }
}
