//! Профиль мимикрии для Яндекс.Музыка
//!
//! Имитирует HTTP-трафик аудиостриминга Яндекс.Музыки (music.yandex.ru).
//! Генерирует реалистичные заголовки для MP3/AAC стриминга.

use bytes::{BufMut, Bytes, BytesMut};
use rand::{rngs::OsRng, Rng, RngCore};
use std::time::Duration;

use crate::error::{MimicryError, Result};
use crate::timing::TimingProfile;

/// User-Agent строки для Яндекс.Музыка клиентов
const USER_AGENTS: &[&str] = &[
    "YandexMusic/5.37 (Android 13; Pixel 6 Pro)",
    "YandexMusic/5.36 (iOS 16.5; iPhone 14 Pro)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Yandex/23.5.4",
    "YandexMusicDesktop/5.0.5",
];

/// Форматы аудио
const AUDIO_FORMATS: &[&str] = &["mp3", "aac", "m4a"];

/// Битрейты
const BITRATES: &[&str] = &["128", "192", "256", "320"];

/// Профиль мимикрии Яндекс.Музыка
pub struct YandexMusicProfile {
    /// Генератор случайных чисел
    rng: OsRng,
    /// Timing профиль для имитации паттернов трафика
    timing: TimingProfile,
}

impl YandexMusicProfile {
    /// Создать новый профиль
    pub fn new() -> Self {
        Self {
            rng: OsRng,
            timing: TimingProfile::audio_streaming(),
        }
    }

    /// Генерация HTTP запроса для аудио chunk
    ///
    /// Пример:
    /// ```
    /// GET /get-mp3/a1b2c3d4/3.mp3 HTTP/1.1
    /// Host: music.yandex.ru
    /// User-Agent: YandexMusic/5.37
    /// X-Yandex-Music-Client: Android
    /// ```
    pub fn generate_request(&mut self, track_id: u64) -> Bytes {
        let user_agent = self.random_user_agent();
        let session_token = self.generate_session_token();
        let format = self.random_format();
        let bitrate = self.random_bitrate();
        let hash = self.generate_hash();

        let request = format!(
            "GET /get-{}/{}_{}.{} HTTP/1.1\r\n\
             Host: music.yandex.ru\r\n\
             User-Agent: {}\r\n\
             Accept: */*\r\n\
             Accept-Encoding: gzip, deflate\r\n\
             Connection: keep-alive\r\n\
             X-Yandex-Music-Client: web\r\n\
             X-Yandex-Music-Session: {}\r\n\
             X-Yandex-Music-Bitrate: {}\r\n\
             Referer: https://music.yandex.ru/\r\n\
             Origin: https://music.yandex.ru\r\n\
             Cookie: yandexuid={}\r\n\
             \r\n",
            format, track_id, bitrate, format, user_agent, session_token, bitrate, hash
        );

        Bytes::from(request)
    }

    /// Генерация HTTP ответа с зашифрованными данными
    ///
    /// Обёртывает зашифрованный payload в HTTP 200 OK ответ,
    /// имитируя аудио stream.
    pub fn generate_response(&mut self, encrypted_payload: &[u8]) -> Bytes {
        let session_token = self.generate_session_token();
        let content_length = encrypted_payload.len();
        let format = self.random_format();

        let mut response = BytesMut::new();

        // HTTP заголовки
        let content_type = match format {
            "mp3" => "audio/mpeg",
            "aac" => "audio/aac",
            "m4a" => "audio/mp4",
            _ => "audio/mpeg",
        };

        let headers = format!(
            "HTTP/1.1 200 OK\r\n\
             Server: nginx\r\n\
             Date: {}\r\n\
             Content-Type: {}\r\n\
             Content-Length: {}\r\n\
             Connection: keep-alive\r\n\
             X-Yandex-Music-Session: {}\r\n\
             X-Yandex-Req-Id: {}\r\n\
             Accept-Ranges: bytes\r\n\
             Cache-Control: public, max-age=86400\r\n\
             Access-Control-Allow-Origin: https://music.yandex.ru\r\n\
             Timing-Allow-Origin: https://music.yandex.ru\r\n\
             \r\n",
            self.current_http_date(),
            content_type,
            content_length,
            session_token,
            self.generate_request_id()
        );

        response.put(headers.as_bytes());
        response.put(encrypted_payload);

        response.freeze()
    }

    /// Получить timing для следующего пакета (steady для аудио)
    pub fn next_packet_timing(&mut self) -> Duration {
        self.timing.next_delay(&mut self.rng)
    }

    /// Получить рекомендуемый размер chunk (для аудио обычно 16-64 KB)
    pub fn recommended_chunk_size(&mut self) -> usize {
        self.rng.gen_range(16 * 1024..64 * 1024)
    }

    /// Генерация случайного session token
    fn generate_session_token(&mut self) -> String {
        let mut bytes = [0u8; 20];
        self.rng.fill_bytes(&mut bytes);
        hex::encode(bytes)
    }

    /// Генерация хеша для cookie
    fn generate_hash(&mut self) -> String {
        let mut bytes = [0u8; 10];
        self.rng.fill_bytes(&mut bytes);
        hex::encode(bytes)
    }

    /// Генерация request ID
    fn generate_request_id(&mut self) -> String {
        format!(
            "{}-{}-{}-{}-{}",
            self.rng.gen::<u32>(),
            self.rng.gen::<u16>(),
            self.rng.gen::<u16>(),
            self.rng.gen::<u16>(),
            self.rng.gen::<u32>()
        )
    }

    /// Случайный User-Agent
    fn random_user_agent(&mut self) -> &'static str {
        USER_AGENTS[self.rng.gen_range(0..USER_AGENTS.len())]
    }

    /// Случайный формат аудио
    fn random_format(&mut self) -> &'static str {
        AUDIO_FORMATS[self.rng.gen_range(0..AUDIO_FORMATS.len())]
    }

    /// Случайный битрейт
    fn random_bitrate(&mut self) -> &'static str {
        BITRATES[self.rng.gen_range(0..BITRATES.len())]
    }

    /// Текущая дата в HTTP формате
    fn current_http_date(&self) -> String {
        use chrono::Utc;
        Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string()
    }
}

impl Default for YandexMusicProfile {
    fn default() -> Self {
        Self::new()
    }
}

/// Парсинг Yandex Music запроса/ответа
pub struct YandexMusicParser;

impl YandexMusicParser {
    /// Извлечь payload из HTTP запроса
    pub fn extract_request_payload(data: &[u8]) -> Result<Bytes> {
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
        let mut profile = YandexMusicProfile::new();
        let request = profile.generate_request(54321);

        let request_str = String::from_utf8_lossy(&request);
        assert!(request_str.contains("GET /get-"));
        assert!(request_str.contains("Host: music.yandex.ru"));
        assert!(request_str.contains("User-Agent: "));
        assert!(request_str.contains("X-Yandex-Music-Session: "));
    }

    #[test]
    fn test_generate_response() {
        let mut profile = YandexMusicProfile::new();
        let payload = b"encrypted audio data";
        let response = profile.generate_response(payload);

        let response_str = String::from_utf8_lossy(&response);
        assert!(response_str.contains("HTTP/1.1 200 OK"));
        assert!(response_str.contains("Content-Type: audio/"));
        assert!(response_str.contains("X-Yandex-Music-Session: "));

        // Проверка, что payload в конце
        assert!(response.ends_with(payload));
    }

    #[test]
    fn test_extract_response_payload() {
        let mut profile = YandexMusicProfile::new();
        let original_payload = b"test audio data";
        let response = profile.generate_response(original_payload);

        let extracted = YandexMusicParser::extract_response_payload(&response).unwrap();
        assert_eq!(&extracted[..], original_payload);
    }

    #[test]
    fn test_chunk_size() {
        let mut profile = YandexMusicProfile::new();
        let size = profile.recommended_chunk_size();
        assert!(size >= 16 * 1024);
        assert!(size <= 64 * 1024);
    }

    #[test]
    fn test_timing() {
        let mut profile = YandexMusicProfile::new();
        let timing = profile.next_packet_timing();
        // Audio streaming имеет более стабильный timing
        assert!(timing.as_millis() >= 50);
        assert!(timing.as_millis() <= 200);
    }
}
