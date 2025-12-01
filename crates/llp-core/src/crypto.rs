//! Криптографические примитивы для LLP
//!
//! Этот модуль предоставляет обёртки над криптографическими операциями:
//! - X25519: обмен ключами Диффи-Хеллмана на эллиптических кривых
//! - ChaCha20-Poly1305: AEAD шифрование
//! - HKDF-SHA256: деривация ключей
//! - Ed25519: цифровые подписи
//! - BLAKE3: криптографическое хеширование
//!
//! Все секретные данные автоматически зануляются при удалении (Zeroize).

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{CryptoError, Result};

/// Размер ключа X25519 (32 байта)
pub const X25519_KEY_SIZE: usize = 32;

/// Размер ключа ChaCha20 (32 байта)
pub const CHACHA20_KEY_SIZE: usize = 32;

/// Размер nonce для ChaCha20-Poly1305 (12 байт)
pub const CHACHA20_NONCE_SIZE: usize = 12;

/// Размер auth tag Poly1305 (16 байт)
pub const POLY1305_TAG_SIZE: usize = 16;

/// Размер случайных данных для handshake (32 байта)
pub const RANDOM_SIZE: usize = 32;

/// Размер подписи Ed25519 (64 байта)
pub const ED25519_SIGNATURE_SIZE: usize = 64;

/// Размер хеша BLAKE3 (32 байта)
pub const BLAKE3_HASH_SIZE: usize = 32;

/// Ключ X25519 (автоматически зануляется)
#[derive(Clone, ZeroizeOnDrop)]
pub struct X25519Key {
    secret: StaticSecret,
    public: PublicKey,
}

impl X25519Key {
    /// Генерация нового ключа X25519
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let secret = StaticSecret::random_from_rng(rng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Получить публичный ключ
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Получить байты публичного ключа
    pub fn public_bytes(&self) -> [u8; X25519_KEY_SIZE] {
        self.public.to_bytes()
    }

    /// Создать из существующего секретного ключа
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != X25519_KEY_SIZE {
            return Err(CryptoError::InvalidKeySize {
                expected: X25519_KEY_SIZE,
                actual: bytes.len(),
            }
            .into());
        }

        let mut key_bytes = [0u8; X25519_KEY_SIZE];
        key_bytes.copy_from_slice(bytes);

        let secret = StaticSecret::from(key_bytes);
        let public = PublicKey::from(&secret);

        key_bytes.zeroize();

        Ok(Self { secret, public })
    }

    /// Выполнить обмен ключами Диффи-Хеллмана
    pub fn diffie_hellman(&self, their_public: &PublicKey) -> SharedSecret {
        let shared = self.secret.diffie_hellman(their_public);
        SharedSecret {
            bytes: shared.to_bytes(),
        }
    }
}

/// Общий секрет после обмена ключами (автоматически зануляется)
#[derive(ZeroizeOnDrop)]
pub struct SharedSecret {
    bytes: [u8; X25519_KEY_SIZE],
}

impl SharedSecret {
    /// Получить байты общего секрета
    pub fn as_bytes(&self) -> &[u8; X25519_KEY_SIZE] {
        &self.bytes
    }

    /// Деривация сессионного ключа через HKDF
    ///
    /// # Параметры
    /// - `salt`: Соль для HKDF (обычно client_random || server_random)
    /// - `info`: Контекстная информация (например, "llp-session-key")
    pub fn derive_session_key(&self, salt: &[u8], info: &[u8]) -> Result<SessionKey> {
        let hkdf = Hkdf::<Sha256>::new(Some(salt), &self.bytes);

        let mut okm = [0u8; CHACHA20_KEY_SIZE];
        hkdf.expand(info, &mut okm)
            .map_err(|e| CryptoError::KeyDerivationError(e.to_string()))?;

        Ok(SessionKey::from_bytes(&okm))
    }
}

/// Сессионный ключ для шифрования (автоматически зануляется)
#[derive(Clone, ZeroizeOnDrop)]
pub struct SessionKey {
    bytes: [u8; CHACHA20_KEY_SIZE],
}

impl SessionKey {
    /// Создать из байтов
    pub fn from_bytes(bytes: &[u8; CHACHA20_KEY_SIZE]) -> Self {
        Self { bytes: *bytes }
    }

    /// Получить байты ключа
    pub fn as_bytes(&self) -> &[u8; CHACHA20_KEY_SIZE] {
        &self.bytes
    }

    /// Генерация случайного ключа (для тестирования)
    #[cfg(test)]
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; CHACHA20_KEY_SIZE];
        rng.fill_bytes(&mut bytes);
        Self { bytes }
    }
}

/// Nonce для ChaCha20 (счётчик пакетов)
#[derive(Clone, Copy, Debug)]
pub struct ChaCha20Nonce {
    counter: u64,
    session_id: u32,
}

impl ChaCha20Nonce {
    /// Создать новый nonce
    pub fn new(session_id: u64, counter: u64) -> Self {
        Self {
            counter,
            session_id: (session_id & 0xFFFFFFFF) as u32,
        }
    }

    /// Преобразовать в байты для ChaCha20
    ///
    /// Формат: [counter (8 bytes) || session_id (4 bytes)]
    pub fn as_bytes(&self) -> [u8; CHACHA20_NONCE_SIZE] {
        let mut nonce = [0u8; CHACHA20_NONCE_SIZE];
        nonce[0..8].copy_from_slice(&self.counter.to_le_bytes());
        nonce[8..12].copy_from_slice(&self.session_id.to_le_bytes());
        nonce
    }

    /// Инкремент счётчика
    pub fn increment(&mut self) -> Result<()> {
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or(CryptoError::NonceOverflow)?;
        Ok(())
    }

    /// Получить текущий счётчик
    pub fn counter(&self) -> u64 {
        self.counter
    }
}

/// AEAD шифровальщик (ChaCha20-Poly1305)
pub struct AeadCipher {
    cipher: ChaCha20Poly1305,
    nonce: ChaCha20Nonce,
}

impl AeadCipher {
    /// Создать новый шифровальщик
    pub fn new(key: &SessionKey, session_id: u64) -> Self {
        let cipher = ChaCha20Poly1305::new(key.as_bytes().into());
        let nonce = ChaCha20Nonce::new(session_id, 0);
        Self { cipher, nonce }
    }

    /// Зашифровать данные с дополнительными аутентифицированными данными (AAD)
    ///
    /// # Параметры
    /// - `plaintext`: Открытые данные для шифрования
    /// - `aad`: Дополнительные аутентифицированные данные (например, заголовок пакета)
    ///
    /// # Возвращает
    /// Зашифрованные данные с auth tag
    pub fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let nonce_bytes = self.nonce.as_bytes();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let payload = Payload {
            msg: plaintext,
            aad,
        };

        let ciphertext = self
            .cipher
            .encrypt(nonce, payload)
            .map_err(|_| CryptoError::EncryptionError)?;

        self.nonce.increment()?;

        Ok(ciphertext)
    }

    /// Расшифровать данные
    ///
    /// # Параметры
    /// - `ciphertext`: Зашифрованные данные с auth tag
    /// - `aad`: Дополнительные аутентифицированные данные
    /// - `nonce_counter`: Счётчик nonce для этого пакета
    ///
    /// # Возвращает
    /// Расшифрованные данные
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        aad: &[u8],
        nonce_counter: u64,
    ) -> Result<Vec<u8>> {
        let nonce = ChaCha20Nonce::new(self.nonce.session_id as u64, nonce_counter);
        let nonce_bytes = nonce.as_bytes();
        let nonce_ref = Nonce::from_slice(&nonce_bytes);

        let payload = Payload {
            msg: ciphertext,
            aad,
        };

        let plaintext = self
            .cipher
            .decrypt(nonce_ref, payload)
            .map_err(|_| CryptoError::DecryptionError)?;

        Ok(plaintext)
    }

    /// Получить текущий счётчик nonce
    pub fn nonce_counter(&self) -> u64 {
        self.nonce.counter()
    }
}

/// Генерация случайных байтов
pub fn random_bytes<R: RngCore + CryptoRng>(rng: &mut R, size: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; size];
    rng.fill_bytes(&mut bytes);
    bytes
}

/// Генерация случайного массива фиксированного размера
pub fn random_array<R: RngCore + CryptoRng, const N: usize>(rng: &mut R) -> [u8; N] {
    let mut bytes = [0u8; N];
    rng.fill_bytes(&mut bytes);
    bytes
}

/// BLAKE3 хеширование
pub fn blake3_hash(data: &[u8]) -> [u8; BLAKE3_HASH_SIZE] {
    let hash = blake3::hash(data);
    *hash.as_bytes()
}

/// HMAC-SHA256 для верификации handshake
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use ring::hmac;

    let signing_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let signature = hmac::sign(&signing_key, data);
    let mut result = [0u8; 32];
    result.copy_from_slice(signature.as_ref());
    result
}

/// Верификация HMAC-SHA256
pub fn verify_hmac_sha256(key: &[u8], data: &[u8], expected_tag: &[u8]) -> bool {
    use ring::hmac;

    let signing_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::verify(&signing_key, data, expected_tag).is_ok()
}

/// Ключ для подписи Ed25519 (автоматически зануляется)
#[derive(ZeroizeOnDrop)]
pub struct Ed25519SigningKey {
    keypair: ed25519_dalek::SigningKey,
}

impl Ed25519SigningKey {
    /// Генерация нового ключа подписи
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let keypair = ed25519_dalek::SigningKey::generate(rng);
        Self { keypair }
    }

    /// Получить публичный ключ для верификации
    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.keypair.verifying_key()
    }

    /// Подписать данные
    pub fn sign(&self, message: &[u8]) -> Result<[u8; ED25519_SIGNATURE_SIZE]> {
        use ed25519_dalek::Signer;

        let signature = self.keypair.sign(message);
        Ok(signature.to_bytes())
    }
}

/// Верификация подписи Ed25519
pub fn verify_ed25519_signature(
    public_key: &ed25519_dalek::VerifyingKey,
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    use ed25519_dalek::{Signature, Verifier};

    if signature.len() != ED25519_SIGNATURE_SIZE {
        return Err(CryptoError::InvalidAuthTagSize {
            expected: ED25519_SIGNATURE_SIZE,
            actual: signature.len(),
        }
        .into());
    }

    let sig = Signature::from_bytes(signature.try_into().unwrap());
    public_key
        .verify(message, &sig)
        .map_err(|_| CryptoError::SignatureVerificationError)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_x25519_key_generation() {
        let mut rng = OsRng;
        let key = X25519Key::generate(&mut rng);
        let public_bytes = key.public_bytes();
        assert_eq!(public_bytes.len(), X25519_KEY_SIZE);
    }

    #[test]
    fn test_x25519_key_exchange() {
        let mut rng = OsRng;

        let alice_key = X25519Key::generate(&mut rng);
        let bob_key = X25519Key::generate(&mut rng);

        let alice_shared = alice_key.diffie_hellman(bob_key.public_key());
        let bob_shared = bob_key.diffie_hellman(alice_key.public_key());

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn test_hkdf_derivation() {
        let mut rng = OsRng;

        let alice_key = X25519Key::generate(&mut rng);
        let bob_key = X25519Key::generate(&mut rng);

        let shared = alice_key.diffie_hellman(bob_key.public_key());

        let salt = b"test_salt";
        let info = b"llp-session-key";

        let session_key = shared.derive_session_key(salt, info).unwrap();
        assert_eq!(session_key.as_bytes().len(), CHACHA20_KEY_SIZE);
    }

    #[test]
    fn test_chacha20_nonce() {
        let mut nonce = ChaCha20Nonce::new(12345, 0);
        assert_eq!(nonce.counter(), 0);

        nonce.increment().unwrap();
        assert_eq!(nonce.counter(), 1);

        let bytes = nonce.as_bytes();
        assert_eq!(bytes.len(), CHACHA20_NONCE_SIZE);
    }

    #[test]
    fn test_nonce_overflow() {
        let mut nonce = ChaCha20Nonce::new(1, u64::MAX);
        let result = nonce.increment();
        assert!(result.is_err());
    }

    #[test]
    fn test_aead_encryption_decryption() {
        let mut rng = OsRng;
        let key = SessionKey::random(&mut rng);

        let mut cipher = AeadCipher::new(&key, 12345);

        let plaintext = b"Hello, LLP!";
        let aad = b"additional authenticated data";

        let ciphertext = cipher.encrypt(plaintext, aad).unwrap();
        assert_ne!(&ciphertext[..plaintext.len()], plaintext);

        let decrypted = cipher.decrypt(&ciphertext, aad, 0).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_aead_wrong_aad() {
        let mut rng = OsRng;
        let key = SessionKey::random(&mut rng);

        let mut cipher = AeadCipher::new(&key, 12345);

        let plaintext = b"Hello, LLP!";
        let aad = b"correct aad";

        let ciphertext = cipher.encrypt(plaintext, aad).unwrap();

        let wrong_aad = b"wrong aad";
        let result = cipher.decrypt(&ciphertext, wrong_aad, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_aead_wrong_key() {
        let mut rng = OsRng;
        let key1 = SessionKey::random(&mut rng);
        let key2 = SessionKey::random(&mut rng);

        let mut cipher1 = AeadCipher::new(&key1, 12345);
        let cipher2 = AeadCipher::new(&key2, 12345);

        let plaintext = b"Hello, LLP!";
        let aad = b"aad";

        let ciphertext = cipher1.encrypt(plaintext, aad).unwrap();
        let result = cipher2.decrypt(&ciphertext, aad, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_blake3_hash() {
        let data = b"test data";
        let hash1 = blake3_hash(data);
        let hash2 = blake3_hash(data);

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), BLAKE3_HASH_SIZE);

        let different_data = b"different data";
        let hash3 = blake3_hash(different_data);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_hmac_sha256() {
        let key = b"secret key";
        let data = b"message to authenticate";

        let tag = hmac_sha256(key, data);
        assert_eq!(tag.len(), 32);

        assert!(verify_hmac_sha256(key, data, &tag));
        assert!(!verify_hmac_sha256(key, b"wrong data", &tag));
        assert!(!verify_hmac_sha256(b"wrong key", data, &tag));
    }

    #[test]
    fn test_ed25519_signature() {
        let mut rng = OsRng;
        let signing_key = Ed25519SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();

        let message = b"test message";
        let signature = signing_key.sign(message).unwrap();

        assert_eq!(signature.len(), ED25519_SIGNATURE_SIZE);
        assert!(verify_ed25519_signature(&verifying_key, message, &signature).is_ok());

        let wrong_message = b"wrong message";
        assert!(verify_ed25519_signature(&verifying_key, wrong_message, &signature).is_err());
    }

    #[test]
    fn test_random_bytes() {
        let mut rng = OsRng;
        let bytes1 = random_bytes(&mut rng, 32);
        let bytes2 = random_bytes(&mut rng, 32);

        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn test_random_array() {
        let mut rng = OsRng;
        let arr1: [u8; 32] = random_array(&mut rng);
        let arr2: [u8; 32] = random_array(&mut rng);

        assert_ne!(arr1, arr2);
    }
}
