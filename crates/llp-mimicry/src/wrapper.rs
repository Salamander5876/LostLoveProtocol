//! Обёртка пакетов LLP в мимикрию
//!
//! Этот модуль отвечает за упаковку зашифрованных LLP пакетов
//! в HTTP-подобный трафик выбранного профиля мимикрии.

use bytes::Bytes;
use llp_core::packet::MimicryProfile;
use std::time::Duration;

use crate::error::Result;
use crate::profiles::{
    RuTubeParser, RuTubeProfile, VkVideoParser, VkVideoProfile, YandexMusicParser,
    YandexMusicProfile,
};

/// Обёртка для пакетов LLP
///
/// Упаковывает зашифрованные LLP пакеты в HTTP-трафик
/// в зависимости от выбранного профиля мимикрии.
pub struct PacketWrapper {
    profile: WrapperProfile,
    chunk_counter: u64,
}

/// Внутреннее представление профиля
enum WrapperProfile {
    None,
    VkVideo(VkVideoProfile),
    YandexMusic(YandexMusicProfile),
    RuTube(RuTubeProfile),
}

impl PacketWrapper {
    /// Создать новую обёртку для указанного профиля
    pub fn new(profile: MimicryProfile) -> Self {
        let wrapper_profile = match profile {
            MimicryProfile::None => WrapperProfile::None,
            MimicryProfile::VkVideo => WrapperProfile::VkVideo(VkVideoProfile::new()),
            MimicryProfile::YandexMusic => {
                WrapperProfile::YandexMusic(YandexMusicProfile::new())
            }
            MimicryProfile::RuTube => WrapperProfile::RuTube(RuTubeProfile::new()),
        };

        Self {
            profile: wrapper_profile,
            chunk_counter: 0,
        }
    }

    /// Обернуть сериализованный LLP пакет в HTTP-трафик
    ///
    /// # Параметры
    /// - `packet_data`: Сериализованный LLP пакет (уже зашифрованный)
    ///
    /// # Возвращает
    /// HTTP request/response в зависимости от профиля
    pub fn wrap(&mut self, packet_data: &[u8]) -> Result<Bytes> {
        match &mut self.profile {
            WrapperProfile::None => {
                // Без мимикрии — возвращаем данные как есть
                Ok(Bytes::copy_from_slice(packet_data))
            }
            WrapperProfile::VkVideo(profile) => {
                let response = profile.generate_response(packet_data);
                self.chunk_counter += 1;
                Ok(response)
            }
            WrapperProfile::YandexMusic(profile) => {
                let response = profile.generate_response(packet_data);
                self.chunk_counter += 1;
                Ok(response)
            }
            WrapperProfile::RuTube(profile) => {
                let response = profile.generate_response(packet_data);
                self.chunk_counter += 1;
                Ok(response)
            }
        }
    }

    /// Извлечь LLP пакет из HTTP-трафика
    ///
    /// # Параметры
    /// - `wrapped_data`: HTTP request/response с упакованным пакетом
    ///
    /// # Возвращает
    /// Сериализованный LLP пакет
    pub fn unwrap(&self, wrapped_data: &[u8]) -> Result<Bytes> {
        match &self.profile {
            WrapperProfile::None => {
                // Без мимикрии — возвращаем данные как есть
                Ok(Bytes::copy_from_slice(wrapped_data))
            }
            WrapperProfile::VkVideo(_) => VkVideoParser::extract_response_payload(wrapped_data),
            WrapperProfile::YandexMusic(_) => {
                YandexMusicParser::extract_response_payload(wrapped_data)
            }
            WrapperProfile::RuTube(_) => RuTubeParser::extract_response_payload(wrapped_data),
        }
    }

    /// Получить рекомендуемую задержку для следующего пакета
    pub fn next_packet_timing(&mut self) -> Duration {
        match &mut self.profile {
            WrapperProfile::None => Duration::from_millis(0),
            WrapperProfile::VkVideo(profile) => profile.next_packet_timing(),
            WrapperProfile::YandexMusic(profile) => profile.next_packet_timing(),
            WrapperProfile::RuTube(profile) => profile.next_packet_timing(),
        }
    }

    /// Получить рекомендуемый размер chunk для профиля
    pub fn recommended_chunk_size(&mut self) -> usize {
        match &mut self.profile {
            WrapperProfile::None => 1024 * 1024, // 1 MB по умолчанию
            WrapperProfile::VkVideo(profile) => profile.recommended_chunk_size(),
            WrapperProfile::YandexMusic(profile) => profile.recommended_chunk_size(),
            WrapperProfile::RuTube(profile) => profile.recommended_chunk_size(),
        }
    }

    /// Сгенерировать HTTP запрос для профиля (опционально)
    ///
    /// Используется для имитации двустороннего HTTP-трафика.
    pub fn generate_request(&mut self) -> Result<Bytes> {
        match &mut self.profile {
            WrapperProfile::None => Ok(Bytes::new()),
            WrapperProfile::VkVideo(profile) => {
                Ok(profile.generate_request(self.chunk_counter))
            }
            WrapperProfile::YandexMusic(profile) => {
                Ok(profile.generate_request(self.chunk_counter))
            }
            WrapperProfile::RuTube(profile) => {
                Ok(profile.generate_request(self.chunk_counter, 0))
            }
        }
    }

    /// Получить текущий счётчик chunk
    pub fn chunk_counter(&self) -> u64 {
        self.chunk_counter
    }
}

/// Статическая утилита для быстрого обёртывания без состояния
pub struct QuickWrapper;

impl QuickWrapper {
    /// Обернуть пакет в профиль мимикрии (без сохранения состояния)
    pub fn wrap(profile: MimicryProfile, packet_data: &[u8]) -> Result<Bytes> {
        let mut wrapper = PacketWrapper::new(profile);
        wrapper.wrap(packet_data)
    }

    /// Извлечь пакет из профиля мимикрии
    pub fn unwrap(profile: MimicryProfile, wrapped_data: &[u8]) -> Result<Bytes> {
        let wrapper = PacketWrapper::new(profile);
        wrapper.unwrap(wrapped_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrapper_vk_video() {
        let mut wrapper = PacketWrapper::new(MimicryProfile::VkVideo);
        let original_data = b"test llp packet data";

        let wrapped = wrapper.wrap(original_data).unwrap();
        assert!(wrapped.len() > original_data.len());

        let unwrapped = wrapper.unwrap(&wrapped).unwrap();
        assert_eq!(&unwrapped[..], original_data);
    }

    #[test]
    fn test_wrapper_yandex_music() {
        let mut wrapper = PacketWrapper::new(MimicryProfile::YandexMusic);
        let original_data = b"test llp packet data";

        let wrapped = wrapper.wrap(original_data).unwrap();
        let unwrapped = wrapper.unwrap(&wrapped).unwrap();
        assert_eq!(&unwrapped[..], original_data);
    }

    #[test]
    fn test_wrapper_rutube() {
        let mut wrapper = PacketWrapper::new(MimicryProfile::RuTube);
        let original_data = b"test llp packet data";

        let wrapped = wrapper.wrap(original_data).unwrap();
        let unwrapped = wrapper.unwrap(&wrapped).unwrap();
        assert_eq!(&unwrapped[..], original_data);
    }

    #[test]
    fn test_wrapper_none() {
        let mut wrapper = PacketWrapper::new(MimicryProfile::None);
        let original_data = b"test llp packet data";

        let wrapped = wrapper.wrap(original_data).unwrap();
        assert_eq!(&wrapped[..], original_data);

        let unwrapped = wrapper.unwrap(&wrapped).unwrap();
        assert_eq!(&unwrapped[..], original_data);
    }

    #[test]
    fn test_quick_wrapper() {
        let original_data = b"quick wrap test";

        let wrapped = QuickWrapper::wrap(MimicryProfile::VkVideo, original_data).unwrap();
        let unwrapped =
            QuickWrapper::unwrap(MimicryProfile::VkVideo, &wrapped).unwrap();

        assert_eq!(&unwrapped[..], original_data);
    }

    #[test]
    fn test_chunk_counter() {
        let mut wrapper = PacketWrapper::new(MimicryProfile::VkVideo);
        assert_eq!(wrapper.chunk_counter(), 0);

        wrapper.wrap(b"test1").unwrap();
        assert_eq!(wrapper.chunk_counter(), 1);

        wrapper.wrap(b"test2").unwrap();
        assert_eq!(wrapper.chunk_counter(), 2);
    }

    #[test]
    fn test_timing() {
        let mut wrapper = PacketWrapper::new(MimicryProfile::VkVideo);
        let timing = wrapper.next_packet_timing();
        assert!(timing.as_millis() <= 1000);
    }

    #[test]
    fn test_chunk_size() {
        let mut wrapper_video = PacketWrapper::new(MimicryProfile::VkVideo);
        let size_video = wrapper_video.recommended_chunk_size();
        assert!(size_video >= 64 * 1024);

        let mut wrapper_audio = PacketWrapper::new(MimicryProfile::YandexMusic);
        let size_audio = wrapper_audio.recommended_chunk_size();
        assert!(size_audio >= 16 * 1024);
        assert!(size_audio <= 64 * 1024);
    }
}
