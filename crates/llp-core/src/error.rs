//! Типы ошибок для LostLoveProtocol
//!
//! Этот модуль содержит все возможные типы ошибок, которые могут возникнуть
//! при работе с протоколом LLP.

use thiserror::Error;

/// Основной тип ошибок протокола LLP
#[derive(Error, Debug)]
pub enum LlpError {
    /// Ошибка сериализации/десериализации пакета
    #[error("Ошибка работы с пакетом: {0}")]
    PacketError(#[from] PacketError),

    /// Ошибка криптографических операций
    #[error("Криптографическая ошибка: {0}")]
    CryptoError(#[from] CryptoError),

    /// Ошибка установления соединения (handshake)
    #[error("Ошибка handshake: {0}")]
    HandshakeError(#[from] HandshakeError),

    /// Ошибка управления сессией
    #[error("Ошибка сессии: {0}")]
    SessionError(#[from] SessionError),

    /// Ошибка ввода-вывода
    #[error("Ошибка I/O: {0}")]
    Io(#[from] std::io::Error),

    /// Общая ошибка
    #[error("Общая ошибка: {0}")]
    Other(String),
}

/// Ошибки при работе с пакетами
#[derive(Error, Debug)]
pub enum PacketError {
    /// Неподдерживаемая версия протокола
    #[error("Неподдерживаемая версия протокола: {0}")]
    UnsupportedVersion(u8),

    /// Некорректный размер пакета
    #[error("Некорректный размер пакета: ожидается минимум {expected}, получено {actual}")]
    InvalidPacketSize { expected: usize, actual: usize },

    /// Некорректный размер payload
    #[error("Некорректный размер payload: заявлено {declared}, реально {actual}")]
    InvalidPayloadSize { declared: usize, actual: usize },

    /// Превышен максимальный размер пакета
    #[error("Превышен максимальный размер пакета: {size} > {max}")]
    PacketTooLarge { size: usize, max: usize },

    /// Некорректные флаги пакета
    #[error("Некорректные флаги пакета: {0:08b}")]
    InvalidFlags(u8),

    /// Некорректный размер padding
    #[error("Некорректный размер padding: {size} > {max}")]
    InvalidPaddingSize { size: usize, max: usize },

    /// Ошибка парсинга заголовка
    #[error("Ошибка парсинга заголовка пакета")]
    HeaderParseError,

    /// Недостаточно данных для парсинга
    #[error("Недостаточно данных: требуется {required}, доступно {available}")]
    InsufficientData { required: usize, available: usize },

    /// Некорректная последовательность фрагментов
    #[error("Некорректная последовательность фрагментов")]
    InvalidFragmentSequence,

    /// Ошибка сериализации
    #[error("Ошибка сериализации пакета: {0}")]
    SerializationError(String),
}

/// Ошибки криптографических операций
#[derive(Error, Debug)]
pub enum CryptoError {
    /// Ошибка генерации ключа
    #[error("Ошибка генерации ключа: {0}")]
    KeyGenerationError(String),

    /// Ошибка обмена ключами (X25519)
    #[error("Ошибка обмена ключами X25519")]
    KeyExchangeError,

    /// Ошибка деривации ключа (HKDF)
    #[error("Ошибка деривации ключа HKDF: {0}")]
    KeyDerivationError(String),

    /// Ошибка шифрования
    #[error("Ошибка шифрования данных")]
    EncryptionError,

    /// Ошибка расшифровки
    #[error("Ошибка расшифровки данных (возможно, неверный ключ или повреждённые данные)")]
    DecryptionError,

    /// Ошибка аутентификации (неверный auth tag)
    #[error("Ошибка аутентификации: неверный auth tag")]
    AuthenticationError,

    /// Ошибка подписи (Ed25519)
    #[error("Ошибка создания подписи Ed25519")]
    SignatureError,

    /// Ошибка верификации подписи
    #[error("Ошибка верификации подписи: подпись недействительна")]
    SignatureVerificationError,

    /// Некорректный размер ключа
    #[error("Некорректный размер ключа: ожидается {expected}, получено {actual}")]
    InvalidKeySize { expected: usize, actual: usize },

    /// Некорректный размер nonce
    #[error("Некорректный размер nonce: ожидается {expected}, получено {actual}")]
    InvalidNonceSize { expected: usize, actual: usize },

    /// Некорректный размер auth tag
    #[error("Некорректный размер auth tag: ожидается {expected}, получено {actual}")]
    InvalidAuthTagSize { expected: usize, actual: usize },

    /// Переполнение nonce (требуется rekey)
    #[error("Переполнение nonce: требуется rekey")]
    NonceOverflow,

    /// Ошибка генерации случайных данных
    #[error("Ошибка генерации случайных данных: {0}")]
    RandomGenerationError(String),
}

/// Ошибки процесса handshake
#[derive(Error, Debug)]
pub enum HandshakeError {
    /// Неожиданное сообщение handshake
    #[error("Неожиданное сообщение handshake: ожидается {expected}, получено {actual}")]
    UnexpectedMessage { expected: String, actual: String },

    /// Неподдерживаемый профиль мимикрии
    #[error("Неподдерживаемый профиль мимикрии: {0}")]
    UnsupportedMimicryProfile(u16),

    /// Тайм-аут handshake
    #[error("Тайм-аут handshake: превышено время ожидания {timeout_ms} мс")]
    Timeout { timeout_ms: u64 },

    /// Некорректный формат сообщения
    #[error("Некорректный формат сообщения handshake")]
    InvalidMessageFormat,

    /// Ошибка верификации handshake
    #[error("Ошибка верификации handshake: HMAC не совпадает")]
    VerificationFailed,

    /// Handshake уже завершён
    #[error("Handshake уже завершён для сессии {session_id}")]
    AlreadyCompleted { session_id: u64 },

    /// Некорректное состояние state machine
    #[error("Некорректное состояние handshake state machine: {0}")]
    InvalidState(String),

    /// Повторное использование client_random или server_random
    #[error("Обнаружено повторное использование random value (replay attack?)")]
    ReplayDetected,
}

/// Ошибки управления сессией
#[derive(Error, Debug)]
pub enum SessionError {
    /// Сессия не найдена
    #[error("Сессия {session_id} не найдена")]
    SessionNotFound { session_id: u64 },

    /// Сессия истекла
    #[error("Сессия {session_id} истекла")]
    SessionExpired { session_id: u64 },

    /// Дублирующийся sequence number (replay attack)
    #[error("Дублирующийся sequence number {seq} в сессии {session_id} (replay attack?)")]
    DuplicateSequenceNumber { session_id: u64, seq: u32 },

    /// Sequence number вне окна приёма
    #[error("Sequence number {seq} вне окна приёма для сессии {session_id}")]
    SequenceOutOfWindow { session_id: u64, seq: u32 },

    /// Превышен лимит активных сессий
    #[error("Превышен лимит активных сессий: {current} > {max}")]
    TooManySessions { current: usize, max: usize },

    /// Сессия уже существует
    #[error("Сессия {session_id} уже существует")]
    SessionAlreadyExists { session_id: u64 },

    /// Требуется rekey
    #[error("Сессия {session_id} требует rekey")]
    RekeyRequired { session_id: u64 },

    /// Ошибка при rekey
    #[error("Ошибка rekey для сессии {session_id}: {reason}")]
    RekeyFailed { session_id: u64, reason: String },

    /// Некорректный timestamp (слишком старый или из будущего)
    #[error("Некорректный timestamp для сессии {session_id}: разница {delta_sec} сек")]
    InvalidTimestamp { session_id: u64, delta_sec: i64 },

    /// Keepalive timeout
    #[error("Keepalive timeout для сессии {session_id}")]
    KeepaliveTimeout { session_id: u64 },
}

/// Псевдоним для Result с ошибкой LLP
pub type Result<T> = std::result::Result<T, LlpError>;

impl From<&str> for LlpError {
    fn from(s: &str) -> Self {
        LlpError::Other(s.to_string())
    }
}

impl From<String> for LlpError {
    fn from(s: String) -> Self {
        LlpError::Other(s)
    }
}
