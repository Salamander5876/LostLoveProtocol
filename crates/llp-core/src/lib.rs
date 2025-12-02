//! # LostLoveProtocol Core (llp-core)
//!
//! Ядро протокола LLP — кастомный VPN протокол с мимикрией под российские сервисы.
//!
//! ## Возможности
//!
//! - **Криптография**: X25519 (обмен ключами), ChaCha20-Poly1305 (шифрование),
//!   HKDF-SHA256 (деривация ключей), Ed25519 (подписи), BLAKE3 (хеширование)
//! - **Handshake**: Четырёхэтапный протокол установления соединения
//! - **Пакеты**: Бинарный формат с поддержкой фрагментации и padding
//! - **Сессии**: Управление активными соединениями с replay protection
//! - **Безопасность**: Zeroize для секретных данных, sliding window anti-replay
//!
//! ## Структура
//!
//! - [`packet`]: Формат пакета LLP и сериализация
//! - [`crypto`]: Криптографические примитивы
//! - [`handshake`]: Протокол установления соединения
//! - [`session`]: Управление сессиями
//! - [`error`]: Типы ошибок
//!
//! ## Пример использования
//!
//! ```rust,no_run
//! use llp_core::{
//!     packet::{PacketHeader, PacketFlags, MimicryProfile, LlpPacket},
//!     crypto::{X25519Key, SessionKey},
//!     handshake::{ClientHandshake, ServerHandshake},
//!     session::{SessionManager, Session},
//! };
//! use rand::rngs::OsRng;
//! use bytes::Bytes;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut rng = OsRng;
//!
//! // Клиентская сторона: начать handshake
//! let mut client = ClientHandshake::new(&mut rng, MimicryProfile::VkVideo);
//! let client_hello = client.start(&mut rng)?;
//!
//! // Серверная сторона: обработать CLIENT_HELLO
//! let mut server = ServerHandshake::new(&mut rng, 12345);
//! let (server_hello, profile) = server.process_client_hello(&mut rng, &client_hello)?;
//!
//! // Продолжение handshake...
//! let session_id = client.process_server_hello(&server_hello)?;
//! let client_verify = client.send_client_verify()?;
//! server.process_client_verify(&client_verify)?;
//! let server_verify = server.send_server_verify()?;
//! client.process_server_verify(&server_verify)?;
//!
//! // Теперь обе стороны имеют общий session_key
//! let client_key = client.session_key().unwrap().clone();
//! let server_key = server.session_key().unwrap().clone();
//!
//! // Создание пакета и шифрование
//! let mut header = PacketHeader::new(
//!     PacketFlags::DATA,
//!     session_id,
//!     0,
//!     MimicryProfile::VkVideo,
//! );
//!
//! // Управление сессиями
//! let mut session_manager = SessionManager::new();
//! session_manager.add_session(session_id, client_key, MimicryProfile::VkVideo)?;
//!
//! # Ok(())
//! # }
//! ```

#![warn(missing_docs)]
#![warn(clippy::all)]
#![allow(clippy::single_component_path_imports)]

pub mod crypto;
pub mod error;
pub mod handshake;
pub mod packet;
pub mod session;

// Re-экспорт основных типов для удобства
pub use error::{LlpError, Result};
pub use packet::{LlpPacket, MimicryProfile, PacketFlags, PacketHeader};

/// Версия библиотеки
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Версия протокола
pub const PROTOCOL_VERSION: u8 = packet::PROTOCOL_VERSION;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_protocol_version() {
        assert_eq!(PROTOCOL_VERSION, 1);
    }
}
