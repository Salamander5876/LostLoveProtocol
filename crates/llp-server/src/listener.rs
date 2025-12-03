//! TCP Listener для принятия подключений клиентов
//!
//! Этот модуль отвечает за:
//! - Прослушивание TCP порта
//! - Принятие новых подключений
//! - Обработку handshake с клиентами
//! - Регистрацию сессий

use llp_core::{
    handshake::ServerHandshake,
    packet::MimicryProfile,
    session::SessionManager,
};
use rand::rngs::OsRng;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::client_handler::ClientHandler;
use crate::config::ServerConfig;
use crate::router::RouterHandle;

/// Результат обработки подключения
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// TCP Listener сервера
pub struct LlpListener {
    /// Конфигурация сервера
    config: Arc<ServerConfig>,
    /// TCP listener
    listener: TcpListener,
    /// Менеджер сессий
    session_manager: Arc<RwLock<SessionManager>>,
    /// Роутер для передачи данных
    router: RouterHandle,
}

impl LlpListener {
    /// Создать новый listener
    pub async fn bind(
        config: Arc<ServerConfig>,
        session_manager: Arc<RwLock<SessionManager>>,
        router: RouterHandle,
    ) -> Result<Self> {
        let bind_addr = config.bind_address();
        let listener = TcpListener::bind(bind_addr).await?;

        info!("LLP сервер запущен на {}", bind_addr);

        Ok(Self {
            config,
            listener,
            session_manager,
            router,
        })
    }

    /// Запустить listener (основной цикл)
    pub async fn run(self) -> Result<()> {
        let listener = Arc::new(self);

        loop {
            match listener.listener.accept().await {
                Ok((mut stream, addr)) => {
                    debug!("Новое подключение от {}", addr);

                    // Проверка лимита подключений
                    let session_count = listener.session_manager.read().await.session_count();
                    if session_count >= listener.config.network.max_connections {
                        warn!("Достигнут лимит подключений ({}), отклонено: {}",
                              listener.config.network.max_connections, addr);
                        let _ = stream.shutdown().await;
                        continue;
                    }

                    // Обработка подключения в отдельной задаче
                    let listener_clone = Arc::clone(&listener);
                    tokio::spawn(async move {
                        if let Err(e) = listener_clone.handle_connection(stream, addr).await {
                            error!("Ошибка обработки подключения от {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Ошибка принятия подключения: {}", e);
                }
            }
        }
    }

    /// Обработка отдельного подключения
    async fn handle_connection(&self, mut stream: TcpStream, addr: SocketAddr) -> Result<()> {
        // Установка таймаута на handshake
        let handshake_timeout = self.config.connection_timeout();

        // Выполнение handshake с таймаутом
        let (session_id, mimicry_profile, session_key) = tokio::time::timeout(
            handshake_timeout,
            self.perform_handshake(&mut stream, addr),
        )
        .await??;

        info!(
            "Handshake завершён: session_id={}, profile={}, peer={}",
            session_id, mimicry_profile, addr
        );

        // Создание сессии
        {
            let mut manager = self.session_manager.write().await;
            manager.add_session(session_id, session_key.clone(), mimicry_profile)?;
        }

        info!("Клиент зарегистрирован: session_id={}", session_id);

        // Запуск обработчика клиента в отдельной задаче
        let handler = ClientHandler::new(session_id, stream, session_key, None); // TODO: передать NAT gateway
        tokio::spawn(async move {
            if let Err(e) = handler.run().await {
                error!("Ошибка обработчика клиента {}: {}", session_id, e);
            }
        });

        Ok(())
    }

    /// Выполнение handshake с клиентом
    async fn perform_handshake(
        &self,
        stream: &mut TcpStream,
        addr: SocketAddr,
    ) -> Result<(u64, MimicryProfile, llp_core::crypto::SessionKey)> {
        let mut rng = OsRng;

        // Генерация session_id
        let session_id = rand::random::<u64>();

        // Создание server handshake
        let mut server_handshake = ServerHandshake::new(&mut rng, session_id);

        // 1. Получение CLIENT_HELLO
        let client_hello_len = stream.read_u32().await? as usize;
        if client_hello_len > 4096 {
            return Err("CLIENT_HELLO слишком большой".into());
        }

        let mut client_hello_buf = vec![0u8; client_hello_len];
        stream.read_exact(&mut client_hello_buf).await?;

        debug!("Получен CLIENT_HELLO от {} ({} байт)", addr, client_hello_len);

        // 2. Обработка CLIENT_HELLO и отправка SERVER_HELLO
        let (server_hello, mimicry_profile) = server_handshake
            .process_client_hello(&mut rng, &client_hello_buf)?;

        stream.write_u32(server_hello.len() as u32).await?;
        stream.write_all(&server_hello).await?;
        stream.flush().await?;

        debug!("Отправлен SERVER_HELLO к {} ({} байт)", addr, server_hello.len());

        // 3. Получение CLIENT_VERIFY
        let client_verify_len = stream.read_u32().await? as usize;
        if client_verify_len > 1024 {
            return Err("CLIENT_VERIFY слишком большой".into());
        }

        let mut client_verify_buf = vec![0u8; client_verify_len];
        stream.read_exact(&mut client_verify_buf).await?;

        server_handshake.process_client_verify(&client_verify_buf)?;

        debug!("Получен и проверен CLIENT_VERIFY от {}", addr);

        // 4. Отправка SERVER_VERIFY
        let server_verify = server_handshake.send_server_verify()?;

        stream.write_u32(server_verify.len() as u32).await?;
        stream.write_all(&server_verify).await?;
        stream.flush().await?;

        debug!("Отправлен SERVER_VERIFY к {}", addr);

        // Handshake завершён
        let session_key = server_handshake
            .session_key()
            .ok_or("Сессионный ключ не получен")?
            .clone();

        Ok((session_id, mimicry_profile, session_key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::router::Router;
    use std::time::Duration;

    #[tokio::test]
    async fn test_listener_bind() {
        let config = Arc::new(ServerConfig::default());
        let session_manager = Arc::new(RwLock::new(SessionManager::new()));
        let router = Router::new(session_manager.clone());
        let router_handle = router.handle();

        // Пробуем забиндить на случайный порт
        let mut test_config = (*config).clone();
        test_config.network.port = 0; // OS выберет свободный порт
        let test_config = Arc::new(test_config);

        let result = LlpListener::bind(test_config, session_manager, router_handle).await;
        assert!(result.is_ok());
    }
}
