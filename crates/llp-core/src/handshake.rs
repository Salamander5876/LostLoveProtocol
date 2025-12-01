//! Протокол установления соединения (handshake)
//!
//! Этот модуль реализует четырёхэтапный handshake между клиентом и сервером:
//!
//! 1. Client → Server: CLIENT_HELLO
//!    - client_public_key (X25519)
//!    - client_random (32 bytes)
//!    - mimicry_profile_id
//!
//! 2. Server → Client: SERVER_HELLO
//!    - server_public_key (X25519)
//!    - server_random (32 bytes)
//!    - session_id (8 bytes)
//!
//! 3. Client → Server: CLIENT_VERIFY
//!    - HMAC-SHA256(session_key, transcript)
//!
//! 4. Server → Client: SERVER_VERIFY
//!    - HMAC-SHA256(session_key, transcript)
//!
//! После успешного завершения обе стороны имеют общий session_key,
//! полученный через X25519 + HKDF.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use rand::{CryptoRng, RngCore};
use std::time::Duration;

use crate::crypto::{
    hmac_sha256, random_array, verify_hmac_sha256, SessionKey, X25519Key, RANDOM_SIZE,
    X25519_KEY_SIZE,
};
use crate::error::{HandshakeError, Result};
use crate::packet::MimicryProfile;

/// Размер HMAC тега для верификации
const HMAC_TAG_SIZE: usize = 32;

/// Информация для HKDF деривации ключа
const HKDF_INFO: &[u8] = b"llp-session-key-v1";

/// Тип сообщения handshake
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandshakeMessageType {
    ClientHello = 1,
    ServerHello = 2,
    ClientVerify = 3,
    ServerVerify = 4,
}

impl HandshakeMessageType {
    /// Преобразование из u8
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(HandshakeMessageType::ClientHello),
            2 => Some(HandshakeMessageType::ServerHello),
            3 => Some(HandshakeMessageType::ClientVerify),
            4 => Some(HandshakeMessageType::ServerVerify),
            _ => None,
        }
    }
}

/// Сообщение CLIENT_HELLO
#[derive(Debug, Clone)]
pub struct ClientHello {
    /// Публичный ключ клиента (X25519)
    pub client_public_key: [u8; X25519_KEY_SIZE],
    /// Случайные данные клиента
    pub client_random: [u8; RANDOM_SIZE],
    /// Профиль мимикрии
    pub mimicry_profile: MimicryProfile,
}

impl ClientHello {
    /// Создать новое сообщение CLIENT_HELLO
    pub fn new<R: RngCore + CryptoRng>(
        rng: &mut R,
        client_key: &X25519Key,
        mimicry_profile: MimicryProfile,
    ) -> Self {
        Self {
            client_public_key: client_key.public_bytes(),
            client_random: random_array(rng),
            mimicry_profile,
        }
    }

    /// Сериализовать в байты
    pub fn serialize(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(1 + X25519_KEY_SIZE + RANDOM_SIZE + 2);
        buf.put_u8(HandshakeMessageType::ClientHello as u8);
        buf.put(&self.client_public_key[..]);
        buf.put(&self.client_random[..]);
        buf.put_u16(self.mimicry_profile.to_u16());
        buf.freeze()
    }

    /// Десериализовать из байтов
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        if data.len() < 1 + X25519_KEY_SIZE + RANDOM_SIZE + 2 {
            return Err(HandshakeError::InvalidMessageFormat.into());
        }

        let mut cursor = data;
        let msg_type = cursor.get_u8();

        if HandshakeMessageType::from_u8(msg_type) != Some(HandshakeMessageType::ClientHello)
        {
            return Err(HandshakeError::UnexpectedMessage {
                expected: "CLIENT_HELLO".to_string(),
                actual: format!("type {}", msg_type),
            }
            .into());
        }

        let mut client_public_key = [0u8; X25519_KEY_SIZE];
        cursor.copy_to_slice(&mut client_public_key);

        let mut client_random = [0u8; RANDOM_SIZE];
        cursor.copy_to_slice(&mut client_random);

        let profile_id = cursor.get_u16();
        let mimicry_profile = MimicryProfile::from_u16(profile_id)
            .ok_or(HandshakeError::UnsupportedMimicryProfile(profile_id))?;

        Ok(Self {
            client_public_key,
            client_random,
            mimicry_profile,
        })
    }
}

/// Сообщение SERVER_HELLO
#[derive(Debug, Clone)]
pub struct ServerHello {
    /// Публичный ключ сервера (X25519)
    pub server_public_key: [u8; X25519_KEY_SIZE],
    /// Случайные данные сервера
    pub server_random: [u8; RANDOM_SIZE],
    /// Идентификатор сессии
    pub session_id: u64,
}

impl ServerHello {
    /// Создать новое сообщение SERVER_HELLO
    pub fn new<R: RngCore + CryptoRng>(
        rng: &mut R,
        server_key: &X25519Key,
        session_id: u64,
    ) -> Self {
        Self {
            server_public_key: server_key.public_bytes(),
            server_random: random_array(rng),
            session_id,
        }
    }

    /// Сериализовать в байты
    pub fn serialize(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(1 + X25519_KEY_SIZE + RANDOM_SIZE + 8);
        buf.put_u8(HandshakeMessageType::ServerHello as u8);
        buf.put(&self.server_public_key[..]);
        buf.put(&self.server_random[..]);
        buf.put_u64(self.session_id);
        buf.freeze()
    }

    /// Десериализовать из байтов
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        if data.len() < 1 + X25519_KEY_SIZE + RANDOM_SIZE + 8 {
            return Err(HandshakeError::InvalidMessageFormat.into());
        }

        let mut cursor = data;
        let msg_type = cursor.get_u8();

        if HandshakeMessageType::from_u8(msg_type) != Some(HandshakeMessageType::ServerHello)
        {
            return Err(HandshakeError::UnexpectedMessage {
                expected: "SERVER_HELLO".to_string(),
                actual: format!("type {}", msg_type),
            }
            .into());
        }

        let mut server_public_key = [0u8; X25519_KEY_SIZE];
        cursor.copy_to_slice(&mut server_public_key);

        let mut server_random = [0u8; RANDOM_SIZE];
        cursor.copy_to_slice(&mut server_random);

        let session_id = cursor.get_u64();

        Ok(Self {
            server_public_key,
            server_random,
            session_id,
        })
    }
}

/// Сообщение CLIENT_VERIFY
#[derive(Debug, Clone)]
pub struct ClientVerify {
    /// HMAC тег для верификации
    pub hmac_tag: [u8; HMAC_TAG_SIZE],
}

impl ClientVerify {
    /// Создать новое сообщение CLIENT_VERIFY
    pub fn new(session_key: &SessionKey, transcript: &[u8]) -> Self {
        let hmac_tag = hmac_sha256(session_key.as_bytes(), transcript);
        Self { hmac_tag }
    }

    /// Сериализовать в байты
    pub fn serialize(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(1 + HMAC_TAG_SIZE);
        buf.put_u8(HandshakeMessageType::ClientVerify as u8);
        buf.put(&self.hmac_tag[..]);
        buf.freeze()
    }

    /// Десериализовать из байтов
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        if data.len() < 1 + HMAC_TAG_SIZE {
            return Err(HandshakeError::InvalidMessageFormat.into());
        }

        let mut cursor = data;
        let msg_type = cursor.get_u8();

        if HandshakeMessageType::from_u8(msg_type) != Some(HandshakeMessageType::ClientVerify)
        {
            return Err(HandshakeError::UnexpectedMessage {
                expected: "CLIENT_VERIFY".to_string(),
                actual: format!("type {}", msg_type),
            }
            .into());
        }

        let mut hmac_tag = [0u8; HMAC_TAG_SIZE];
        cursor.copy_to_slice(&mut hmac_tag);

        Ok(Self { hmac_tag })
    }

    /// Верифицировать HMAC
    pub fn verify(&self, session_key: &SessionKey, transcript: &[u8]) -> Result<()> {
        if !verify_hmac_sha256(session_key.as_bytes(), transcript, &self.hmac_tag) {
            return Err(HandshakeError::VerificationFailed.into());
        }
        Ok(())
    }
}

/// Сообщение SERVER_VERIFY
#[derive(Debug, Clone)]
pub struct ServerVerify {
    /// HMAC тег для верификации
    pub hmac_tag: [u8; HMAC_TAG_SIZE],
}

impl ServerVerify {
    /// Создать новое сообщение SERVER_VERIFY
    pub fn new(session_key: &SessionKey, transcript: &[u8]) -> Self {
        let hmac_tag = hmac_sha256(session_key.as_bytes(), transcript);
        Self { hmac_tag }
    }

    /// Сериализовать в байты
    pub fn serialize(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(1 + HMAC_TAG_SIZE);
        buf.put_u8(HandshakeMessageType::ServerVerify as u8);
        buf.put(&self.hmac_tag[..]);
        buf.freeze()
    }

    /// Десериализовать из байтов
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        if data.len() < 1 + HMAC_TAG_SIZE {
            return Err(HandshakeError::InvalidMessageFormat.into());
        }

        let mut cursor = data;
        let msg_type = cursor.get_u8();

        if HandshakeMessageType::from_u8(msg_type) != Some(HandshakeMessageType::ServerVerify)
        {
            return Err(HandshakeError::UnexpectedMessage {
                expected: "SERVER_VERIFY".to_string(),
                actual: format!("type {}", msg_type),
            }
            .into());
        }

        let mut hmac_tag = [0u8; HMAC_TAG_SIZE];
        cursor.copy_to_slice(&mut hmac_tag);

        Ok(Self { hmac_tag })
    }

    /// Верифицировать HMAC
    pub fn verify(&self, session_key: &SessionKey, transcript: &[u8]) -> Result<()> {
        if !verify_hmac_sha256(session_key.as_bytes(), transcript, &self.hmac_tag) {
            return Err(HandshakeError::VerificationFailed.into());
        }
        Ok(())
    }
}

/// Состояние handshake state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    /// Начальное состояние
    Initial,
    /// Отправлен CLIENT_HELLO
    ClientHelloSent,
    /// Получен SERVER_HELLO
    ServerHelloReceived,
    /// Отправлен CLIENT_VERIFY
    ClientVerifySent,
    /// Получен SERVER_VERIFY (handshake завершён)
    Completed,
    /// Получен CLIENT_HELLO (серверная сторона)
    ClientHelloReceived,
    /// Отправлен SERVER_HELLO (серверная сторона)
    ServerHelloSent,
    /// Получен CLIENT_VERIFY (серверная сторона)
    ClientVerifyReceived,
}

/// Handshake контекст для клиента
pub struct ClientHandshake {
    state: HandshakeState,
    client_key: X25519Key,
    mimicry_profile: MimicryProfile,
    client_hello: Option<ClientHello>,
    server_hello: Option<ServerHello>,
    session_key: Option<SessionKey>,
}

impl ClientHandshake {
    /// Создать новый клиентский handshake
    pub fn new<R: RngCore + CryptoRng>(
        rng: &mut R,
        mimicry_profile: MimicryProfile,
    ) -> Self {
        Self {
            state: HandshakeState::Initial,
            client_key: X25519Key::generate(rng),
            mimicry_profile,
            client_hello: None,
            server_hello: None,
            session_key: None,
        }
    }

    /// Начать handshake, отправить CLIENT_HELLO
    pub fn start<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> Result<Bytes> {
        if self.state != HandshakeState::Initial {
            return Err(HandshakeError::InvalidState(format!(
                "Expected Initial, got {:?}",
                self.state
            ))
            .into());
        }

        let client_hello =
            ClientHello::new(rng, &self.client_key, self.mimicry_profile);
        let message = client_hello.serialize();
        self.client_hello = Some(client_hello);
        self.state = HandshakeState::ClientHelloSent;

        Ok(message)
    }

    /// Обработать SERVER_HELLO от сервера
    pub fn process_server_hello(&mut self, data: &[u8]) -> Result<u64> {
        if self.state != HandshakeState::ClientHelloSent {
            return Err(HandshakeError::InvalidState(format!(
                "Expected ClientHelloSent, got {:?}",
                self.state
            ))
            .into());
        }

        let server_hello = ServerHello::deserialize(data)?;
        let session_id = server_hello.session_id;

        // Выполняем обмен ключами Диффи-Хеллмана
        let server_public_key =
            x25519_dalek::PublicKey::from(server_hello.server_public_key);
        let shared_secret = self.client_key.diffie_hellman(&server_public_key);

        // Деривация сессионного ключа через HKDF
        let client_hello = self.client_hello.as_ref().unwrap();
        let mut salt = Vec::with_capacity(RANDOM_SIZE * 2);
        salt.extend_from_slice(&client_hello.client_random);
        salt.extend_from_slice(&server_hello.server_random);

        let session_key = shared_secret.derive_session_key(&salt, HKDF_INFO)?;

        self.server_hello = Some(server_hello);
        self.session_key = Some(session_key);
        self.state = HandshakeState::ServerHelloReceived;

        Ok(session_id)
    }

    /// Отправить CLIENT_VERIFY
    pub fn send_client_verify(&mut self) -> Result<Bytes> {
        if self.state != HandshakeState::ServerHelloReceived {
            return Err(HandshakeError::InvalidState(format!(
                "Expected ServerHelloReceived, got {:?}",
                self.state
            ))
            .into());
        }

        let transcript = self.build_transcript();
        let session_key = self.session_key.as_ref().unwrap();
        let client_verify = ClientVerify::new(session_key, &transcript);
        let message = client_verify.serialize();

        self.state = HandshakeState::ClientVerifySent;
        Ok(message)
    }

    /// Обработать SERVER_VERIFY от сервера
    pub fn process_server_verify(&mut self, data: &[u8]) -> Result<()> {
        if self.state != HandshakeState::ClientVerifySent {
            return Err(HandshakeError::InvalidState(format!(
                "Expected ClientVerifySent, got {:?}",
                self.state
            ))
            .into());
        }

        let server_verify = ServerVerify::deserialize(data)?;

        let transcript = self.build_transcript();
        let session_key = self.session_key.as_ref().unwrap();
        server_verify.verify(session_key, &transcript)?;

        self.state = HandshakeState::Completed;
        Ok(())
    }

    /// Получить сессионный ключ (доступно только после завершения handshake)
    pub fn session_key(&self) -> Option<&SessionKey> {
        if self.state == HandshakeState::Completed {
            self.session_key.as_ref()
        } else {
            None
        }
    }

    /// Проверить, завершён ли handshake
    pub fn is_completed(&self) -> bool {
        self.state == HandshakeState::Completed
    }

    /// Получить session_id (доступен после получения SERVER_HELLO)
    pub fn session_id(&self) -> Option<u64> {
        self.server_hello.as_ref().map(|sh| sh.session_id)
    }

    /// Построить transcript для верификации
    fn build_transcript(&self) -> Vec<u8> {
        let client_hello = self.client_hello.as_ref().unwrap();
        let server_hello = self.server_hello.as_ref().unwrap();

        let mut transcript = Vec::new();
        transcript.extend_from_slice(&client_hello.serialize());
        transcript.extend_from_slice(&server_hello.serialize());
        transcript
    }
}

/// Handshake контекст для сервера
pub struct ServerHandshake {
    state: HandshakeState,
    server_key: X25519Key,
    session_id: u64,
    client_hello: Option<ClientHello>,
    server_hello: Option<ServerHello>,
    session_key: Option<SessionKey>,
}

impl ServerHandshake {
    /// Создать новый серверный handshake
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R, session_id: u64) -> Self {
        Self {
            state: HandshakeState::Initial,
            server_key: X25519Key::generate(rng),
            session_id,
            client_hello: None,
            server_hello: None,
            session_key: None,
        }
    }

    /// Обработать CLIENT_HELLO от клиента
    pub fn process_client_hello<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        data: &[u8],
    ) -> Result<(Bytes, MimicryProfile)> {
        if self.state != HandshakeState::Initial {
            return Err(HandshakeError::InvalidState(format!(
                "Expected Initial, got {:?}",
                self.state
            ))
            .into());
        }

        let client_hello = ClientHello::deserialize(data)?;
        let mimicry_profile = client_hello.mimicry_profile;

        // Выполняем обмен ключами
        let client_public_key =
            x25519_dalek::PublicKey::from(client_hello.client_public_key);
        let shared_secret = self.server_key.diffie_hellman(&client_public_key);

        // Генерируем SERVER_HELLO
        let server_hello = ServerHello::new(rng, &self.server_key, self.session_id);

        // Деривация сессионного ключа
        let mut salt = Vec::with_capacity(RANDOM_SIZE * 2);
        salt.extend_from_slice(&client_hello.client_random);
        salt.extend_from_slice(&server_hello.server_random);

        let session_key = shared_secret.derive_session_key(&salt, HKDF_INFO)?;

        let message = server_hello.serialize();

        self.client_hello = Some(client_hello);
        self.server_hello = Some(server_hello);
        self.session_key = Some(session_key);
        self.state = HandshakeState::ServerHelloSent;

        Ok((message, mimicry_profile))
    }

    /// Обработать CLIENT_VERIFY от клиента
    pub fn process_client_verify(&mut self, data: &[u8]) -> Result<()> {
        if self.state != HandshakeState::ServerHelloSent {
            return Err(HandshakeError::InvalidState(format!(
                "Expected ServerHelloSent, got {:?}",
                self.state
            ))
            .into());
        }

        let client_verify = ClientVerify::deserialize(data)?;

        let transcript = self.build_transcript();
        let session_key = self.session_key.as_ref().unwrap();
        client_verify.verify(session_key, &transcript)?;

        self.state = HandshakeState::ClientVerifyReceived;
        Ok(())
    }

    /// Отправить SERVER_VERIFY
    pub fn send_server_verify(&mut self) -> Result<Bytes> {
        if self.state != HandshakeState::ClientVerifyReceived {
            return Err(HandshakeError::InvalidState(format!(
                "Expected ClientVerifyReceived, got {:?}",
                self.state
            ))
            .into());
        }

        let transcript = self.build_transcript();
        let session_key = self.session_key.as_ref().unwrap();
        let server_verify = ServerVerify::new(session_key, &transcript);
        let message = server_verify.serialize();

        self.state = HandshakeState::Completed;
        Ok(message)
    }

    /// Получить сессионный ключ (доступно только после завершения handshake)
    pub fn session_key(&self) -> Option<&SessionKey> {
        if self.state == HandshakeState::Completed {
            self.session_key.as_ref()
        } else {
            None
        }
    }

    /// Проверить, завершён ли handshake
    pub fn is_completed(&self) -> bool {
        self.state == HandshakeState::Completed
    }

    /// Получить профиль мимикрии (доступен после получения CLIENT_HELLO)
    pub fn mimicry_profile(&self) -> Option<MimicryProfile> {
        self.client_hello.as_ref().map(|ch| ch.mimicry_profile)
    }

    /// Построить transcript для верификации
    fn build_transcript(&self) -> Vec<u8> {
        let client_hello = self.client_hello.as_ref().unwrap();
        let server_hello = self.server_hello.as_ref().unwrap();

        let mut transcript = Vec::new();
        transcript.extend_from_slice(&client_hello.serialize());
        transcript.extend_from_slice(&server_hello.serialize());
        transcript
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_client_hello_serialization() {
        let mut rng = OsRng;
        let key = X25519Key::generate(&mut rng);
        let client_hello = ClientHello::new(&mut rng, &key, MimicryProfile::VkVideo);

        let serialized = client_hello.serialize();
        let deserialized = ClientHello::deserialize(&serialized).unwrap();

        assert_eq!(
            client_hello.client_public_key,
            deserialized.client_public_key
        );
        assert_eq!(client_hello.client_random, deserialized.client_random);
        assert_eq!(
            client_hello.mimicry_profile,
            deserialized.mimicry_profile
        );
    }

    #[test]
    fn test_server_hello_serialization() {
        let mut rng = OsRng;
        let key = X25519Key::generate(&mut rng);
        let server_hello = ServerHello::new(&mut rng, &key, 12345);

        let serialized = server_hello.serialize();
        let deserialized = ServerHello::deserialize(&serialized).unwrap();

        assert_eq!(
            server_hello.server_public_key,
            deserialized.server_public_key
        );
        assert_eq!(server_hello.server_random, deserialized.server_random);
        assert_eq!(server_hello.session_id, deserialized.session_id);
    }

    #[test]
    fn test_full_handshake() {
        let mut rng = OsRng;

        // Инициализация клиента и сервера
        let mut client = ClientHandshake::new(&mut rng, MimicryProfile::VkVideo);
        let mut server = ServerHandshake::new(&mut rng, 12345);

        // 1. CLIENT_HELLO
        let client_hello_msg = client.start(&mut rng).unwrap();

        // 2. SERVER_HELLO
        let (server_hello_msg, profile) = server
            .process_client_hello(&mut rng, &client_hello_msg)
            .unwrap();
        assert_eq!(profile, MimicryProfile::VkVideo);

        // Клиент обрабатывает SERVER_HELLO
        let session_id = client.process_server_hello(&server_hello_msg).unwrap();
        assert_eq!(session_id, 12345);

        // 3. CLIENT_VERIFY
        let client_verify_msg = client.send_client_verify().unwrap();
        server.process_client_verify(&client_verify_msg).unwrap();

        // 4. SERVER_VERIFY
        let server_verify_msg = server.send_server_verify().unwrap();
        client.process_server_verify(&server_verify_msg).unwrap();

        // Проверка завершения
        assert!(client.is_completed());
        assert!(server.is_completed());

        // Проверка, что ключи совпадают
        let client_key = client.session_key().unwrap();
        let server_key = server.session_key().unwrap();
        assert_eq!(client_key.as_bytes(), server_key.as_bytes());
    }

    #[test]
    fn test_handshake_invalid_state() {
        let mut rng = OsRng;
        let mut client = ClientHandshake::new(&mut rng, MimicryProfile::None);

        // Попытка отправить CLIENT_VERIFY без получения SERVER_HELLO
        let result = client.send_client_verify();
        assert!(result.is_err());
    }

    #[test]
    fn test_handshake_wrong_hmac() {
        let mut rng = OsRng;

        let mut client = ClientHandshake::new(&mut rng, MimicryProfile::None);
        let mut server = ServerHandshake::new(&mut rng, 1);

        let client_hello_msg = client.start(&mut rng).unwrap();
        let (server_hello_msg, _) = server
            .process_client_hello(&mut rng, &client_hello_msg)
            .unwrap();
        client.process_server_hello(&server_hello_msg).unwrap();

        // Подделываем CLIENT_VERIFY с неверным HMAC
        let fake_verify = ClientVerify {
            hmac_tag: [0xAAu8; HMAC_TAG_SIZE],
        };
        let fake_msg = fake_verify.serialize();

        let result = server.process_client_verify(&fake_msg);
        assert!(result.is_err());
    }
}
