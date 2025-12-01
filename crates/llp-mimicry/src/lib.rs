//! # LLP Mimicry (llp-mimicry)
//!
//! Система мимикрии для LostLoveProtocol.
//!
//! Этот крейт отвечает за обёртывание зашифрованных LLP пакетов в HTTP-трафик,
//! имитирующий легитимные российские сервисы:
//! - VK Video (vkvideo.ru)
//! - Яндекс.Музыка (music.yandex.ru)
//! - RuTube (rutube.ru)
//!
//! ## Возможности
//!
//! - Генерация реалистичных HTTP заголовков
//! - Имитация паттернов трафика (burst для видео, steady для аудио)
//! - Случайные timing delays
//! - Упаковка/распаковка LLP пакетов
//!
//! ## Пример использования
//!
//! ```rust,no_run
//! use llp_mimicry::{PacketWrapper, QuickWrapper};
//! use llp_core::packet::MimicryProfile;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Создание обёртки для VK Video профиля
//! let mut wrapper = PacketWrapper::new(MimicryProfile::VkVideo);
//!
//! // Обёртывание LLP пакета в HTTP-трафик
//! let llp_packet_data = b"encrypted llp packet";
//! let wrapped = wrapper.wrap(llp_packet_data)?;
//!
//! // wrapped теперь выглядит как HTTP ответ от vkvideo.ru
//! println!("Wrapped size: {} bytes", wrapped.len());
//!
//! // Извлечение оригинального пакета
//! let unwrapped = wrapper.unwrap(&wrapped)?;
//! assert_eq!(&unwrapped[..], llp_packet_data);
//!
//! // Быстрое обёртывание без состояния
//! let quick_wrapped = QuickWrapper::wrap(
//!     MimicryProfile::YandexMusic,
//!     llp_packet_data
//! )?;
//!
//! # Ok(())
//! # }
//! ```

#![deny(missing_docs)]
#![warn(clippy::all)]

pub mod error;
pub mod profiles;
pub mod timing;
pub mod wrapper;

// Re-экспорт основных типов
pub use error::{MimicryError, Result};
pub use timing::TimingProfile;
pub use wrapper::{PacketWrapper, QuickWrapper};

/// Версия библиотеки
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }
}
