//! Профили мимикрии для различных сервисов

pub mod rutube;
pub mod vk_video;
pub mod yandex_music;

pub use rutube::{RuTubeParser, RuTubeProfile};
pub use vk_video::{VkVideoParser, VkVideoProfile};
pub use yandex_music::{YandexMusicParser, YandexMusicProfile};
