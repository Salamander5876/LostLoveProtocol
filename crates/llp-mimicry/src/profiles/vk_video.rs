//! Профиль мимикрии для VK Video
//!
//! Имитирует HTTP-трафик видеостриминга VK Video (vkvideo.ru).
//! Генерирует реалистичные заголовки, паттерны трафика и timing.

use bytes::{BufMut, Bytes, BytesMut};
use rand::{rngs::OsRng, Rng, RngCore};
use std::time::Duration;

use crate::error::{MimicryError, Result};
use crate::timing::TimingProfile;

/// User-Agent строки для VK клиентов
const USER_AGENTS: &[&str] = &[
    "VKClient/8.34 (Android 13; SDK 33; armeabi-v7a; Samsung SM-G991B; ru)",
    "VKClient/8.33 (iOS 16.5; iPhone14,2; Scale/3.00)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 VK/8.34",
    "VKDesktop/5.4.2 (Windows 10.0.19045)",
];

/// Возможные качества видео
const VIDEO_QUALITIES: &[&str] = &["240", "360", "480", "720", "1080"];

/// Форматы видео
const VIDEO_FORMATS: &[&str] = &["mp4", "webm", "ts"];

/// Профиль мимикрии VK Video
pub struct VkVideoProfile {
    /// Генератор случайных чисел
    rng: OsRng,
    /// Timing профиль для имитации паттернов трафика
    timing: TimingProfile,
}

impl VkVideoProfile {
    /// Создать новый профиль
    pub fn new() -> Self {
        Self {
            rng: OsRng,
            timing: TimingProfile::video_streaming(),
        }
    }

    /// Генерация HTTP запроса для chunk видео
    ///
    /// Пример:
    /// ```
    /// GET /video/chunk_1234567890.ts HTTP/1.1
    /// Host: vkvideo.ru
    /// User-Agent: VKClient/8.34
    /// X-VK-Session: a1b2c3d4e5f6
    /// Range: bytes=1048576-2097152
    /// ```
    pub fn generate_request(&mut self, chunk_id: u64) -> Bytes {
        let user_agent = self.random_user_agent();
        let session_id = self.generate_session_id();
        let quality = self.random_quality();
        let format = self.random_format();

        let request = format!(
            "GET /video/chunk_{}_{}.{} HTTP/1.1\r\n\
             Host: vkvideo.ru\r\n\
             User-Agent: {}\r\n\
             Accept: */*\r\n\
             Accept-Encoding: gzip, deflate\r\n\
             Connection: keep-alive\r\n\
             X-VK-Session: {}\r\n\
             X-VK-Quality: {}\r\n\
             Referer: https://vk.com/video\r\n\
             Origin: https://vk.com\r\n\
             \r\n",
            chunk_id, quality, format, user_agent, session_id, quality
        );

        Bytes::from(request)
    }

    /// Генерация HTTP ответа с зашифрованными данными
    ///
    /// Обёртывает зашифрованный payload в HTTP 206 Partial Content ответ,
    /// имитируя chunk видео.
    pub fn generate_response(&mut self, encrypted_payload: &[u8]) -> Bytes {
        let session_id = self.generate_session_id();
        let content_length = encrypted_payload.len();

        // Генерируем реалистичные Range заголовки
        let range_start = self.rng.gen_range(0..10_000_000);
        let range_end = range_start + content_length;

        let mut response = BytesMut::new();

        // HTTP заголовки
        let headers = format!(
            "HTTP/1.1 206 Partial Content\r\n\
             Server: nginx/1.20.2\r\n\
             Date: {}\r\n\
             Content-Type: video/mp2t\r\n\
             Content-Length: {}\r\n\
             Content-Range: bytes {}-{}/50000000\r\n\
             Connection: keep-alive\r\n\
             X-VK-Session: {}\r\n\
             X-VK-Server: vkvideo42\r\n\
             Accept-Ranges: bytes\r\n\
             Cache-Control: public, max-age=31536000\r\n\
             Access-Control-Allow-Origin: https://vk.com\r\n\
             \r\n",
            self.current_http_date(),
            content_length,
            range_start,
            range_end - 1,
            session_id
        );

        response.put(headers.as_bytes());
        response.put(encrypted_payload);

        response.freeze()
    }

    /// Получить timing для следующего пакета (burst для видео)
    pub fn next_packet_timing(&mut self) -> Duration {
        self.timing.next_delay(&mut self.rng)
    }

    /// Получить рекомендуемый размер chunk (для видео обычно 64-256 KB)
    pub fn recommended_chunk_size(&mut self) -> usize {
        self.rng.gen_range(64 * 1024..256 * 1024)
    }

    /// Генерация случайного session ID
    fn generate_session_id(&mut self) -> String {
        let mut bytes = [0u8; 16];
        self.rng.fill_bytes(&mut bytes);
        hex::encode(bytes)
    }

    /// Случайный User-Agent
    fn random_user_agent(&mut self) -> &'static str {
        USER_AGENTS[self.rng.gen_range(0..USER_AGENTS.len())]
    }

    /// Случайное качество видео
    fn random_quality(&mut self) -> &'static str {
        VIDEO_QUALITIES[self.rng.gen_range(0..VIDEO_QUALITIES.len())]
    }

    /// Случайный формат видео
    fn random_format(&mut self) -> &'static str {
        VIDEO_FORMATS[self.rng.gen_range(0..VIDEO_FORMATS.len())]
    }

    /// Текущая дата в HTTP формате
    fn current_http_date(&self) -> String {
        use chrono::Utc;
        Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string()
    }
}

impl Default for VkVideoProfile {
    fn default() -> Self {
        Self::new()
    }
}

/// Парсинг VK Video запроса для извлечения зашифрованных данных
pub struct VkVideoParser;

impl VkVideoParser {
    /// Извлечь payload из HTTP запроса
    pub fn extract_request_payload(data: &[u8]) -> Result<Bytes> {
        // VK Video запросы обычно GET без body, payload в URL параметрах не передаётся
        // Для LLP мы можем использовать POST с payload в body
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut req = httparse::Request::new(&mut headers);

        let header_size = match req.parse(data)
            .map_err(|e| MimicryError::ParseError(format!("HTTP parse error: {:?}", e)))? {
            httparse::Status::Complete(size) => size,
            httparse::Status::Partial => {
                return Err(MimicryError::ParseError("Incomplete HTTP request".to_string()).into());
            }
        };

        if header_size >= data.len() {
            return Ok(Bytes::new());
        }

        Ok(Bytes::copy_from_slice(&data[header_size..]))
    }

    /// Извлечь payload из HTTP ответа
    pub fn extract_response_payload(data: &[u8]) -> Result<Bytes> {
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut resp = httparse::Response::new(&mut headers);

        let header_size = match resp.parse(data)
            .map_err(|e| MimicryError::ParseError(format!("HTTP parse error: {:?}", e)))? {
            httparse::Status::Complete(size) => size,
            httparse::Status::Partial => {
                return Err(MimicryError::ParseError("Incomplete HTTP response".to_string()).into());
            }
        };

        if header_size >= data.len() {
            return Err(MimicryError::ParseError("No payload in response".to_string()).into());
        }

        Ok(Bytes::copy_from_slice(&data[header_size..]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_request() {
        let mut profile = VkVideoProfile::new();
        let request = profile.generate_request(12345);

        let request_str = String::from_utf8_lossy(&request);
        assert!(request_str.contains("GET /video/chunk_"));
        assert!(request_str.contains("Host: vkvideo.ru"));
        assert!(request_str.contains("User-Agent: "));
        assert!(request_str.contains("X-VK-Session: "));
    }

    #[test]
    fn test_generate_response() {
        let mut profile = VkVideoProfile::new();
        let payload = b"encrypted data here";
        let response = profile.generate_response(payload);

        let response_str = String::from_utf8_lossy(&response);
        assert!(response_str.contains("HTTP/1.1 206 Partial Content"));
        assert!(response_str.contains("Content-Type: video/mp2t"));
        assert!(response_str.contains("X-VK-Session: "));

        // Проверка, что payload в конце
        assert!(response.ends_with(payload));
    }

    #[test]
    fn test_extract_response_payload() {
        let mut profile = VkVideoProfile::new();
        let original_payload = b"test encrypted data";
        let response = profile.generate_response(original_payload);

        let extracted = VkVideoParser::extract_response_payload(&response).unwrap();
        assert_eq!(&extracted[..], original_payload);
    }

    #[test]
    fn test_chunk_size() {
        let mut profile = VkVideoProfile::new();
        let size = profile.recommended_chunk_size();
        assert!(size >= 64 * 1024);
        assert!(size <= 256 * 1024);
    }

    #[test]
    fn test_timing() {
        let mut profile = VkVideoProfile::new();
        let timing = profile.next_packet_timing();
        assert!(timing.as_millis() <= 1000);
    }
}
