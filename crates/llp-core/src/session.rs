//! Управление сессиями LLP
//!
//! Этот модуль отвечает за управление активными сессиями VPN-соединений:
//! - Хранение сессионных ключей
//! - Replay protection через sliding window
//! - Управление nonce/счётчиками пакетов
//! - Timeout и keepalive
//! - Rekey mechanism

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::crypto::{AeadCipher, SessionKey};
use crate::error::{Result, SessionError};
use crate::packet::{LlpPacket, MimicryProfile, PacketFlags};

/// Размер окна для replay protection (количество пакетов)
const REPLAY_WINDOW_SIZE: usize = 256;

/// Максимальное количество одновременных сессий
const MAX_SESSIONS: usize = 1000;

/// Время жизни сессии по умолчанию (24 часа)
const DEFAULT_SESSION_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);

/// Интервал keepalive (30 секунд)
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

/// Timeout для keepalive (90 секунд)
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(90);

/// Максимальный допустимый drift времени между клиентом и сервером (5 минут)
const MAX_TIMESTAMP_DRIFT: Duration = Duration::from_secs(5 * 60);

/// Информация об активной сессии
pub struct Session {
    /// Идентификатор сессии
    session_id: u64,
    /// Сессионный ключ
    session_key: SessionKey,
    /// Шифровальщик для исходящих пакетов
    tx_cipher: AeadCipher,
    /// Дешифратор для входящих пакетов
    rx_cipher: AeadCipher,
    /// Профиль мимикрии
    mimicry_profile: MimicryProfile,
    /// Время создания сессии
    created_at: Instant,
    /// Время последней активности
    last_activity: Instant,
    /// Время последнего полученного keepalive
    last_keepalive: Instant,
    /// Счётчик отправленных пакетов
    tx_sequence: u32,
    /// Окно для replay protection входящих пакетов
    rx_replay_window: ReplayWindow,
    /// Требуется ли rekey
    rekey_required: bool,
}

impl Session {
    /// Создать новую сессию
    pub fn new(
        session_id: u64,
        session_key: SessionKey,
        mimicry_profile: MimicryProfile,
    ) -> Self {
        let tx_cipher = AeadCipher::new(&session_key, session_id);
        let rx_cipher = AeadCipher::new(&session_key, session_id);
        let now = Instant::now();

        Self {
            session_id,
            session_key,
            tx_cipher,
            rx_cipher,
            mimicry_profile,
            created_at: now,
            last_activity: now,
            last_keepalive: now,
            tx_sequence: 0,
            rx_replay_window: ReplayWindow::new(REPLAY_WINDOW_SIZE),
            rekey_required: false,
        }
    }

    /// Получить ID сессии
    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    /// Получить профиль мимикрии
    pub fn mimicry_profile(&self) -> MimicryProfile {
        self.mimicry_profile
    }

    /// Зашифровать payload для отправки
    ///
    /// Возвращает (encrypted_payload, sequence_number)
    pub fn encrypt_payload(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<(Vec<u8>, u32)> {
        let ciphertext = self.tx_cipher.encrypt(plaintext, aad)?;
        let sequence = self.tx_sequence;

        self.tx_sequence = self
            .tx_sequence
            .checked_add(1)
            .ok_or_else(|| SessionError::RekeyRequired {
                session_id: self.session_id,
            })?;

        // Проверка на необходимость rekey (каждые 2^31 пакетов)
        if self.tx_sequence >= (1u32 << 31) {
            self.rekey_required = true;
        }

        self.last_activity = Instant::now();
        Ok((ciphertext, sequence))
    }

    /// Расшифровать входящий payload
    pub fn decrypt_payload(
        &mut self,
        ciphertext: &[u8],
        aad: &[u8],
        sequence_number: u32,
    ) -> Result<Vec<u8>> {
        // Replay protection: проверка через sliding window
        if !self.rx_replay_window.check_and_update(sequence_number) {
            return Err(SessionError::DuplicateSequenceNumber {
                session_id: self.session_id,
                seq: sequence_number,
            }
            .into());
        }

        let plaintext = self
            .rx_cipher
            .decrypt(ciphertext, aad, sequence_number as u64)?;

        self.last_activity = Instant::now();
        self.last_keepalive = Instant::now();

        Ok(plaintext)
    }

    /// Проверить timestamp пакета
    pub fn validate_timestamp(&self, packet_timestamp: u32) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let packet_time = packet_timestamp as i64;
        let delta = (now - packet_time).abs();

        if delta > MAX_TIMESTAMP_DRIFT.as_secs() as i64 {
            return Err(SessionError::InvalidTimestamp {
                session_id: self.session_id,
                delta_sec: delta,
            }
            .into());
        }

        Ok(())
    }

    /// Проверить, истекла ли сессия
    pub fn is_expired(&self, lifetime: Duration) -> bool {
        self.created_at.elapsed() > lifetime
    }

    /// Проверить, требуется ли keepalive
    pub fn needs_keepalive(&self) -> bool {
        self.last_activity.elapsed() > KEEPALIVE_INTERVAL
    }

    /// Проверить keepalive timeout
    pub fn is_keepalive_timeout(&self) -> bool {
        self.last_keepalive.elapsed() > KEEPALIVE_TIMEOUT
    }

    /// Проверить, требуется ли rekey
    pub fn needs_rekey(&self) -> bool {
        self.rekey_required
    }

    /// Отметить, что keepalive получен
    pub fn mark_keepalive_received(&mut self) {
        self.last_keepalive = Instant::now();
        self.last_activity = Instant::now();
    }

    /// Получить время с последней активности
    pub fn idle_time(&self) -> Duration {
        self.last_activity.elapsed()
    }

    /// Получить текущий TX sequence number
    pub fn current_tx_sequence(&self) -> u32 {
        self.tx_sequence
    }
}

/// Sliding window для replay protection
///
/// Использует битовую маску для отслеживания полученных пакетов
/// в окне размером REPLAY_WINDOW_SIZE.
struct ReplayWindow {
    /// Максимальный полученный sequence number
    highest_seq: u32,
    /// Битовая маска для отслеживания полученных пакетов
    window: VecDeque<bool>,
    /// Размер окна
    window_size: usize,
}

impl ReplayWindow {
    /// Создать новое окно
    fn new(window_size: usize) -> Self {
        Self {
            highest_seq: 0,
            window: VecDeque::with_capacity(window_size),
            window_size,
        }
    }

    /// Проверить и обновить окно
    ///
    /// Возвращает true, если пакет новый и должен быть обработан.
    /// Возвращает false, если пакет дублирующийся (replay attack).
    fn check_and_update(&mut self, seq: u32) -> bool {
        // Первый пакет
        if self.window.is_empty() {
            self.highest_seq = seq;
            self.window.push_back(true);
            return true;
        }

        // Пакет с sequence больше текущего максимума
        if seq > self.highest_seq {
            let diff = (seq - self.highest_seq) as usize;

            if diff >= self.window_size {
                // Окно сдвигается полностью
                self.window.clear();
                self.window.push_back(true);
            } else {
                // Добавляем false для пропущенных пакетов
                for _ in 0..diff - 1 {
                    self.window.push_back(false);
                    if self.window.len() > self.window_size {
                        self.window.pop_front();
                    }
                }
                // Добавляем текущий пакет
                self.window.push_back(true);
                if self.window.len() > self.window_size {
                    self.window.pop_front();
                }
            }

            self.highest_seq = seq;
            return true;
        }

        // Пакет внутри окна
        let diff = (self.highest_seq - seq) as usize;

        if diff >= self.window.len() {
            // Пакет слишком старый, вне окна
            return false;
        }

        let index = self.window.len() - 1 - diff;

        // Проверка дубликата
        if self.window[index] {
            return false; // Дубликат
        }

        // Отмечаем пакет как полученный
        self.window[index] = true;
        true
    }
}

/// Менеджер сессий
pub struct SessionManager {
    /// Карта активных сессий: session_id -> Session
    sessions: HashMap<u64, Session>,
    /// Время жизни сессии
    session_lifetime: Duration,
}

impl SessionManager {
    /// Создать новый менеджер сессий
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            session_lifetime: DEFAULT_SESSION_LIFETIME,
        }
    }

    /// Создать новый менеджер с кастомным временем жизни сессии
    pub fn with_lifetime(session_lifetime: Duration) -> Self {
        Self {
            sessions: HashMap::new(),
            session_lifetime,
        }
    }

    /// Добавить новую сессию
    pub fn add_session(
        &mut self,
        session_id: u64,
        session_key: SessionKey,
        mimicry_profile: MimicryProfile,
    ) -> Result<()> {
        // Проверка лимита сессий
        if self.sessions.len() >= MAX_SESSIONS {
            return Err(SessionError::TooManySessions {
                current: self.sessions.len(),
                max: MAX_SESSIONS,
            }
            .into());
        }

        // Проверка существования сессии
        if self.sessions.contains_key(&session_id) {
            return Err(SessionError::SessionAlreadyExists { session_id }.into());
        }

        let session = Session::new(session_id, session_key, mimicry_profile);
        self.sessions.insert(session_id, session);

        Ok(())
    }

    /// Получить мутабельную ссылку на сессию
    pub fn get_session_mut(&mut self, session_id: u64) -> Result<&mut Session> {
        self.sessions
            .get_mut(&session_id)
            .ok_or_else(|| SessionError::SessionNotFound { session_id }.into())
    }

    /// Получить ссылку на сессию
    pub fn get_session(&self, session_id: u64) -> Result<&Session> {
        self.sessions
            .get(&session_id)
            .ok_or_else(|| SessionError::SessionNotFound { session_id }.into())
    }

    /// Удалить сессию
    pub fn remove_session(&mut self, session_id: u64) -> Result<()> {
        self.sessions
            .remove(&session_id)
            .ok_or_else(|| SessionError::SessionNotFound { session_id })?;
        Ok(())
    }

    /// Очистить истёкшие сессии
    pub fn cleanup_expired(&mut self) -> usize {
        let initial_count = self.sessions.len();

        self.sessions.retain(|_, session| {
            !session.is_expired(self.session_lifetime)
                && !session.is_keepalive_timeout()
        });

        initial_count - self.sessions.len()
    }

    /// Получить список сессий, требующих keepalive
    pub fn sessions_needing_keepalive(&self) -> Vec<u64> {
        self.sessions
            .iter()
            .filter(|(_, session)| session.needs_keepalive())
            .map(|(id, _)| *id)
            .collect()
    }

    /// Получить список сессий, требующих rekey
    pub fn sessions_needing_rekey(&self) -> Vec<u64> {
        self.sessions
            .iter()
            .filter(|(_, session)| session.needs_rekey())
            .map(|(id, _)| *id)
            .collect()
    }

    /// Получить количество активных сессий
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Проверить, существует ли сессия
    pub fn has_session(&self, session_id: u64) -> bool {
        self.sessions.contains_key(&session_id)
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SessionKey;
    use rand::rngs::OsRng;

    #[test]
    fn test_session_creation() {
        let mut rng = OsRng;
        let key = SessionKey::random(&mut rng);
        let session = Session::new(12345, key, MimicryProfile::VkVideo);

        assert_eq!(session.session_id(), 12345);
        assert_eq!(session.mimicry_profile(), MimicryProfile::VkVideo);
        assert_eq!(session.current_tx_sequence(), 0);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let mut rng = OsRng;
        let key = SessionKey::random(&mut rng);
        let mut session = Session::new(1, key, MimicryProfile::None);

        let plaintext = b"Hello, LLP!";
        let aad = b"additional data";

        let (ciphertext, seq) = session.encrypt_payload(plaintext, aad).unwrap();
        assert_eq!(seq, 0);

        let decrypted = session.decrypt_payload(&ciphertext, aad, seq).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_replay_protection() {
        let mut rng = OsRng;
        let key = SessionKey::random(&mut rng);
        let mut session = Session::new(1, key, MimicryProfile::None);

        let plaintext = b"test";
        let aad = b"aad";

        let (ciphertext, seq) = session.encrypt_payload(plaintext, aad).unwrap();

        // Первая расшифровка успешна
        let result1 = session.decrypt_payload(&ciphertext, aad, seq);
        assert!(result1.is_ok());

        // Повторная расшифровка с тем же sequence number должна быть отклонена
        let result2 = session.decrypt_payload(&ciphertext, aad, seq);
        assert!(result2.is_err());
    }

    #[test]
    fn test_replay_window() {
        let mut window = ReplayWindow::new(256);

        // Первый пакет
        assert!(window.check_and_update(0));

        // Следующие пакеты
        assert!(window.check_and_update(1));
        assert!(window.check_and_update(2));

        // Дубликат
        assert!(!window.check_and_update(1));

        // Пакет вне порядка, но в окне
        assert!(window.check_and_update(5));
        assert!(window.check_and_update(3));

        // Пакет далеко впереди
        assert!(window.check_and_update(300));

        // Старый пакет вне окна
        assert!(!window.check_and_update(10));
    }

    #[test]
    fn test_session_manager() {
        let mut rng = OsRng;
        let mut manager = SessionManager::new();

        let key1 = SessionKey::random(&mut rng);
        let key2 = SessionKey::random(&mut rng);

        // Добавление сессий
        manager
            .add_session(1, key1, MimicryProfile::VkVideo)
            .unwrap();
        manager
            .add_session(2, key2, MimicryProfile::YandexMusic)
            .unwrap();

        assert_eq!(manager.session_count(), 2);
        assert!(manager.has_session(1));
        assert!(manager.has_session(2));

        // Получение сессии
        let session = manager.get_session(1).unwrap();
        assert_eq!(session.session_id(), 1);

        // Удаление сессии
        manager.remove_session(1).unwrap();
        assert_eq!(manager.session_count(), 1);
        assert!(!manager.has_session(1));
    }

    #[test]
    fn test_session_already_exists() {
        let mut rng = OsRng;
        let mut manager = SessionManager::new();

        let key = SessionKey::random(&mut rng);

        manager.add_session(1, key.clone(), MimicryProfile::None).unwrap();

        let result = manager.add_session(1, key, MimicryProfile::None);
        assert!(result.is_err());
    }

    #[test]
    fn test_session_not_found() {
        let manager = SessionManager::new();
        let result = manager.get_session(999);
        assert!(result.is_err());
    }

    #[test]
    fn test_timestamp_validation() {
        let mut rng = OsRng;
        let key = SessionKey::random(&mut rng);
        let session = Session::new(1, key, MimicryProfile::None);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        // Валидный timestamp
        assert!(session.validate_timestamp(now).is_ok());

        // Timestamp из будущего (в пределах допустимого drift)
        assert!(session.validate_timestamp(now + 60).is_ok());

        // Timestamp слишком старый
        let old_timestamp = now - (MAX_TIMESTAMP_DRIFT.as_secs() as u32 + 100);
        assert!(session.validate_timestamp(old_timestamp).is_err());

        // Timestamp слишком далеко в будущем
        let future_timestamp = now + (MAX_TIMESTAMP_DRIFT.as_secs() as u32 + 100);
        assert!(session.validate_timestamp(future_timestamp).is_err());
    }

    #[test]
    fn test_keepalive_tracking() {
        let mut rng = OsRng;
        let key = SessionKey::random(&mut rng);
        let mut session = Session::new(1, key, MimicryProfile::None);

        // Симуляция времени через sleep недоступна в unit-тестах,
        // но можно проверить начальное состояние
        assert!(!session.needs_keepalive());
        assert!(!session.is_keepalive_timeout());

        session.mark_keepalive_received();
        assert!(!session.is_keepalive_timeout());
    }
}
