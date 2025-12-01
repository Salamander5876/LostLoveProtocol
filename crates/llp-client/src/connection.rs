//! Управление подключением к серверу
//!
//! Этот модуль отвечает за:
//! - Установление TCP подключения к серверу
//! - Выполнение handshake
//! - Отправку и получение LLP пакетов
//! - Автоматическое переподключение

use bytes::Bytes;
use llp_core::{
    handshake::ClientHandshake,
    packet::{LlpPacket, MimicryProfile, PacketFlags, PacketHeader},
    session::Session,
};
use llp_mimicry::PacketWrapper;
use rand::rngs::OsRng;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::config::ClientConfig;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Состояние подключения
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Отключено
    Disconnected,
    /// Подключение
    Connecting,
    /// Handshake
    Handshaking,
    /// Подключено
    Connected,
    /// Переподключение
    Reconnecting,
}

/// Информация о подключении
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// Состояние
    pub state: ConnectionState,
    /// Session ID (если подключено)
    pub session_id: Option<u64>,
    /// Профиль мимикрии
    pub mimicry_profile: MimicryProfile,
    /// Количество попыток переподключения
    pub reconnect_attempts: u32,
}

/// Подключение к серверу LLP
pub struct ServerConnection {
    /// Конфигурация
    config: Arc<ClientConfig>,
    /// TCP stream
    stream: Option<TcpStream>,
    /// Информация о подключении
    info: Arc<RwLock<ConnectionInfo>>,
    /// Wrapper для мимикрии
    wrapper: Option<PacketWrapper>,
    /// Сессия
    session: Option<Session>,
}

impl ServerConnection {
    /// Создать новое подключение
    pub fn new(config: Arc<ClientConfig>) -> Self {
        let mimicry_profile = config
            .parse_mimicry_profile()
            .unwrap_or(MimicryProfile::None);

        let info = ConnectionInfo {
            state: ConnectionState::Disconnected,
            session_id: None,
            mimicry_profile,
            reconnect_attempts: 0,
        };

        Self {
            config,
            stream: None,
            info: Arc::new(RwLock::new(info)),
            wrapper: None,
            session: None,
        }
    }

    /// Получить информацию о подключении
    pub fn info(&self) -> Arc<RwLock<ConnectionInfo>> {
        Arc::clone(&self.info)
    }

    /// Подключиться к серверу
    pub async fn connect(&mut self) -> Result<()> {
        self.set_state(ConnectionState::Connecting).await;

        info!("Подключение к серверу: {}", self.config.server_address());

        // Подключение TCP
        let stream = tokio::time::timeout(
            self.config.connection_timeout(),
            TcpStream::connect(self.config.server_address()),
        )
        .await??;

        info!("✓ TCP подключение установлено");

        self.stream = Some(stream);
        self.set_state(ConnectionState::Handshaking).await;

        // Выполнение handshake
        let (session_id, mimicry_profile, session_key) = self.perform_handshake().await?;

        info!(
            "✓ Handshake завершён: session_id={}, profile={}",
            session_id, mimicry_profile
        );

        // Создание сессии
        let session = Session::new(session_id, session_key, mimicry_profile);

        // Создание wrapper
        let wrapper = PacketWrapper::new(mimicry_profile);

        self.session = Some(session);
        self.wrapper = Some(wrapper);

        {
            let mut info = self.info.write().await;
            info.session_id = Some(session_id);
            info.mimicry_profile = mimicry_profile;
            info.reconnect_attempts = 0;
        }

        self.set_state(ConnectionState::Connected).await;

        info!("✓ Подключение установлено");

        Ok(())
    }

    /// Переподключиться к серверу
    pub async fn reconnect(&mut self) -> Result<()> {
        {
            let mut info = self.info.write().await;
            info.reconnect_attempts += 1;
        }

        self.set_state(ConnectionState::Reconnecting).await;

        let attempts = {
            let info = self.info.read().await;
            info.reconnect_attempts
        };

        if attempts > self.config.server.reconnect_attempts {
            return Err("Превышено количество попыток переподключения".into());
        }

        info!("Попытка переподключения #{}", attempts);

        // Задержка перед переподключением
        tokio::time::sleep(self.config.reconnect_delay()).await;

        // Закрытие старого подключения
        self.stream = None;
        self.session = None;
        self.wrapper = None;

        // Новое подключение
        self.connect().await
    }

    /// Отправить IP пакет на сервер
    pub async fn send_packet(&mut self, ip_packet: &[u8]) -> Result<()> {
        let session = self.session.as_mut().ok_or("Нет активной сессии")?;
        let wrapper = self.wrapper.as_mut().ok_or("Нет wrapper")?;
        let stream = self.stream.as_mut().ok_or("Нет подключения")?;

        // Создание заголовка LLP пакета
        let session_id = session.session_id();
        let sequence_number = session.current_tx_sequence();

        let header = PacketHeader::new(
            PacketFlags::DATA,
            session_id,
            sequence_number,
            session.mimicry_profile(),
        );

        // Шифрование payload
        let aad = {
            let mut buf = bytes::BytesMut::new();
            header.serialize(&mut buf);
            buf.freeze()
        };

        let (encrypted_payload, _) = session.encrypt_payload(ip_packet, &aad)?;

        // Создание LLP пакета
        let llp_packet = LlpPacket::new(
            header,
            Bytes::from(encrypted_payload),
            Bytes::new(), // TODO: Добавить padding
            [0u8; 16],    // TODO: Вычислить auth tag
        )?;

        // Сериализация
        let serialized = llp_packet.serialize()?;

        // Обёртывание в мимикрию
        let wrapped = wrapper.wrap(&serialized)?;

        // Отправка
        stream.write_u32(wrapped.len() as u32).await?;
        stream.write_all(&wrapped).await?;
        stream.flush().await?;

        debug!("→ Отправлен пакет: {} байт", wrapped.len());

        Ok(())
    }

    /// Получить IP пакет от сервера
    pub async fn receive_packet(&mut self) -> Result<Bytes> {
        let session = self.session.as_mut().ok_or("Нет активной сессии")?;
        let wrapper = self.wrapper.as_ref().ok_or("Нет wrapper")?;
        let stream = self.stream.as_mut().ok_or("Нет подключения")?;

        // Чтение размера
        let len = stream.read_u32().await? as usize;

        if len > 65536 {
            return Err("Пакет слишком большой".into());
        }

        // Чтение данных
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;

        debug!("← Получен пакет: {} байт", len);

        // Распаковка мимикрии
        let unwrapped = wrapper.unwrap(&buf)?;

        // Десериализация LLP пакета
        let llp_packet = LlpPacket::deserialize(&unwrapped)?;

        // Расшифровка
        let aad = {
            let mut buf = bytes::BytesMut::new();
            llp_packet.header.serialize(&mut buf);
            buf.freeze()
        };

        let plaintext = session.decrypt_payload(
            &llp_packet.encrypted_payload,
            &aad,
            llp_packet.header.sequence_number,
        )?;

        Ok(Bytes::from(plaintext))
    }

    /// Отправить keepalive
    pub async fn send_keepalive(&mut self) -> Result<()> {
        let session = self.session.as_ref().ok_or("Нет активной сессии")?;
        let stream = self.stream.as_mut().ok_or("Нет подключения")?;

        let header = PacketHeader::new(
            PacketFlags::KEEPALIVE,
            session.session_id(),
            session.current_tx_sequence(),
            session.mimicry_profile(),
        );

        // Отправка пустого keepalive пакета
        // TODO: Реализовать полностью

        debug!("→ Отправлен keepalive");

        Ok(())
    }

    /// Проверить, подключено ли
    pub async fn is_connected(&self) -> bool {
        let info = self.info.read().await;
        info.state == ConnectionState::Connected
    }

    /// Выполнить handshake с сервером
    async fn perform_handshake(
        &mut self,
    ) -> Result<(u64, MimicryProfile, llp_core::crypto::SessionKey)> {
        let mut rng = OsRng;
        let stream = self.stream.as_mut().ok_or("Нет подключения")?;

        let mimicry_profile = self.config.parse_mimicry_profile()?;

        // Создание client handshake
        let mut client_handshake = ClientHandshake::new(&mut rng, mimicry_profile);

        // 1. Отправка CLIENT_HELLO
        let client_hello = client_handshake.start(&mut rng)?;
        stream.write_u32(client_hello.len() as u32).await?;
        stream.write_all(&client_hello).await?;
        stream.flush().await?;

        debug!("→ Отправлен CLIENT_HELLO ({} байт)", client_hello.len());

        // 2. Получение SERVER_HELLO
        let server_hello_len = stream.read_u32().await? as usize;
        if server_hello_len > 4096 {
            return Err("SERVER_HELLO слишком большой".into());
        }

        let mut server_hello_buf = vec![0u8; server_hello_len];
        stream.read_exact(&mut server_hello_buf).await?;

        debug!("← Получен SERVER_HELLO ({} байт)", server_hello_len);

        let session_id = client_handshake.process_server_hello(&server_hello_buf)?;

        // 3. Отправка CLIENT_VERIFY
        let client_verify = client_handshake.send_client_verify()?;
        stream.write_u32(client_verify.len() as u32).await?;
        stream.write_all(&client_verify).await?;
        stream.flush().await?;

        debug!("→ Отправлен CLIENT_VERIFY ({} байт)", client_verify.len());

        // 4. Получение SERVER_VERIFY
        let server_verify_len = stream.read_u32().await? as usize;
        if server_verify_len > 1024 {
            return Err("SERVER_VERIFY слишком большой".into());
        }

        let mut server_verify_buf = vec![0u8; server_verify_len];
        stream.read_exact(&mut server_verify_buf).await?;

        debug!("← Получен SERVER_VERIFY ({} байт)", server_verify_len);

        client_handshake.process_server_verify(&server_verify_buf)?;

        // Handshake завершён
        let session_key = client_handshake
            .session_key()
            .ok_or("Не получен сессионный ключ")?
            .clone();

        Ok((session_id, mimicry_profile, session_key))
    }

    /// Установить состояние
    async fn set_state(&self, state: ConnectionState) {
        let mut info = self.info.write().await;
        info.state = state;
    }
}

impl Drop for ServerConnection {
    fn drop(&mut self) {
        if self.stream.is_some() {
            info!("Закрытие подключения к серверу");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_info() {
        let config = Arc::new(ClientConfig::default());
        let conn = ServerConnection::new(config);

        let info_handle = conn.info();
        assert!(info_handle.try_read().is_ok());
    }

    #[test]
    fn test_connection_state() {
        let info = ConnectionInfo {
            state: ConnectionState::Disconnected,
            session_id: None,
            mimicry_profile: MimicryProfile::None,
            reconnect_attempts: 0,
        };

        assert_eq!(info.state, ConnectionState::Disconnected);
        assert!(info.session_id.is_none());
    }
}
