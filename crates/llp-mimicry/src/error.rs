//! Типы ошибок для llp-mimicry

use thiserror::Error;

/// Ошибки модуля мимикрии
#[derive(Error, Debug)]
pub enum MimicryError {
    /// Ошибка парсинга HTTP
    #[error("Ошибка парсинга: {0}")]
    ParseError(String),

    /// Неподдерживаемый профиль
    #[error("Неподдерживаемый профиль мимикрии: {0}")]
    UnsupportedProfile(String),

    /// Некорректный формат данных
    #[error("Некорректный формат данных: {0}")]
    InvalidFormat(String),

    /// Ошибка обёртывания пакета
    #[error("Ошибка обёртывания пакета: {0}")]
    WrapError(String),

    /// Ошибка извлечения пакета
    #[error("Ошибка извлечения пакета: {0}")]
    UnwrapError(String),
}

/// Псевдоним для Result с MimicryError
pub type Result<T> = std::result::Result<T, MimicryError>;
