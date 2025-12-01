//! Формат пакета LostLoveProtocol
//!
//! Этот модуль определяет структуру пакета LLP, включая:
//! - Заголовок с метаданными
//! - Зашифрованный payload
//! - Случайный padding для защиты от анализа размера
//! - Auth tag для аутентификации
//!
//! Формат пакета:
//! ```text
//! ┌──────────────┬──────────────┬──────────────────────────────┐
//! │ Version (8)  │  Flags (8)   │     Payload Length (16)      │
//! ├──────────────┴──────────────┴──────────────────────────────┤
//! │                     Session ID (64)                        │
//! ├────────────────────────────────────────────────────────────┤
//! │                   Sequence Number (32)                     │
//! ├────────────────────────────────────────────────────────────┤
//! │                     Timestamp (32)                         │
//! ├────────────────────────────────────────────────────────────┤
//! │   Mimicry Profile (16)      │    Padding Length (16)       │
//! ├────────────────────────────────────────────────────────────┤
//! │              Encrypted Payload (variable)                  │
//! ├────────────────────────────────────────────────────────────┤
//! │                  Random Padding (0-1024)                   │
//! ├────────────────────────────────────────────────────────────┤
//! │               Auth Tag (Poly1305, 128 bits)                │
//! └────────────────────────────────────────────────────────────┘
//! ```

use bitflags::bitflags;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::fmt;

use crate::error::{PacketError, Result};

/// Текущая версия протокола LLP
pub const PROTOCOL_VERSION: u8 = 1;

/// Размер заголовка пакета (без payload и auth tag)
pub const HEADER_SIZE: usize = 24; // 1 + 1 + 2 + 8 + 4 + 4 + 2 + 2

/// Размер auth tag (Poly1305)
pub const AUTH_TAG_SIZE: usize = 16;

/// Минимальный размер пакета (header + auth tag)
pub const MIN_PACKET_SIZE: usize = HEADER_SIZE + AUTH_TAG_SIZE;

/// Максимальный размер пакета (64 KB)
pub const MAX_PACKET_SIZE: usize = 65536;

/// Максимальный размер payload
pub const MAX_PAYLOAD_SIZE: usize = MAX_PACKET_SIZE - MIN_PACKET_SIZE - 1024; // -1024 для padding

/// Максимальный размер padding
pub const MAX_PADDING_SIZE: usize = 1024;

bitflags! {
    /// Флаги типа и свойств пакета
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct PacketFlags: u8 {
        /// Пакет содержит данные (DATA)
        const DATA       = 0b0000_0001;
        /// Пакет содержит управляющую информацию (CONTROL)
        const CONTROL    = 0b0000_0010;
        /// Пакет является фрагментом (FRAGMENT)
        const FRAGMENT   = 0b0000_0100;
        /// Последний фрагмент в последовательности (LAST_FRAG)
        const LAST_FRAG  = 0b0000_1000;
        /// Подтверждение получения (ACK)
        const ACK        = 0b0001_0000;
        /// Keepalive пакет
        const KEEPALIVE  = 0b0010_0000;
        /// Запрос на rekey
        const REKEY      = 0b0100_0000;
        /// Зарезервировано для будущего использования
        const RESERVED   = 0b1000_0000;
    }
}

impl fmt::Display for PacketFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut flags = Vec::new();
        if self.contains(PacketFlags::DATA) {
            flags.push("DATA");
        }
        if self.contains(PacketFlags::CONTROL) {
            flags.push("CONTROL");
        }
        if self.contains(PacketFlags::FRAGMENT) {
            flags.push("FRAGMENT");
        }
        if self.contains(PacketFlags::LAST_FRAG) {
            flags.push("LAST_FRAG");
        }
        if self.contains(PacketFlags::ACK) {
            flags.push("ACK");
        }
        if self.contains(PacketFlags::KEEPALIVE) {
            flags.push("KEEPALIVE");
        }
        if self.contains(PacketFlags::REKEY) {
            flags.push("REKEY");
        }
        write!(f, "{}", flags.join("|"))
    }
}

/// Идентификатор профиля мимикрии
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum MimicryProfile {
    /// Без мимикрии (чистый протокол)
    None = 0,
    /// Имитация VK Video
    VkVideo = 1,
    /// Имитация Яндекс.Музыка
    YandexMusic = 2,
    /// Имитация RuTube
    RuTube = 3,
}

impl MimicryProfile {
    /// Преобразование из u16
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0 => Some(MimicryProfile::None),
            1 => Some(MimicryProfile::VkVideo),
            2 => Some(MimicryProfile::YandexMusic),
            3 => Some(MimicryProfile::RuTube),
            _ => None,
        }
    }

    /// Преобразование в u16
    pub fn to_u16(self) -> u16 {
        self as u16
    }
}

impl fmt::Display for MimicryProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MimicryProfile::None => write!(f, "None"),
            MimicryProfile::VkVideo => write!(f, "VK Video"),
            MimicryProfile::YandexMusic => write!(f, "Yandex Music"),
            MimicryProfile::RuTube => write!(f, "RuTube"),
        }
    }
}

/// Заголовок пакета LLP
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketHeader {
    /// Версия протокола
    pub version: u8,
    /// Флаги пакета
    pub flags: PacketFlags,
    /// Длина зашифрованного payload
    pub payload_length: u16,
    /// Идентификатор сессии
    pub session_id: u64,
    /// Порядковый номер пакета
    pub sequence_number: u32,
    /// Unix timestamp (секунды)
    pub timestamp: u32,
    /// Профиль мимикрии
    pub mimicry_profile: MimicryProfile,
    /// Длина padding
    pub padding_length: u16,
}

impl PacketHeader {
    /// Создать новый заголовок
    pub fn new(
        flags: PacketFlags,
        session_id: u64,
        sequence_number: u32,
        mimicry_profile: MimicryProfile,
    ) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            flags,
            payload_length: 0,
            session_id,
            sequence_number,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as u32,
            mimicry_profile,
            padding_length: 0,
        }
    }

    /// Сериализовать заголовок в байты
    pub fn serialize(&self, buf: &mut BytesMut) {
        buf.put_u8(self.version);
        buf.put_u8(self.flags.bits());
        buf.put_u16(self.payload_length);
        buf.put_u64(self.session_id);
        buf.put_u32(self.sequence_number);
        buf.put_u32(self.timestamp);
        buf.put_u16(self.mimicry_profile.to_u16());
        buf.put_u16(self.padding_length);
    }

    /// Десериализовать заголовок из байтов
    pub fn deserialize(buf: &mut impl Buf) -> Result<Self> {
        if buf.remaining() < HEADER_SIZE {
            return Err(PacketError::InsufficientData {
                required: HEADER_SIZE,
                available: buf.remaining(),
            }
            .into());
        }

        let version = buf.get_u8();
        if version != PROTOCOL_VERSION {
            return Err(PacketError::UnsupportedVersion(version).into());
        }

        let flags_bits = buf.get_u8();
        let flags = PacketFlags::from_bits(flags_bits)
            .ok_or(PacketError::InvalidFlags(flags_bits))?;

        let payload_length = buf.get_u16();
        let session_id = buf.get_u64();
        let sequence_number = buf.get_u32();
        let timestamp = buf.get_u32();

        let mimicry_profile_id = buf.get_u16();
        let mimicry_profile = MimicryProfile::from_u16(mimicry_profile_id)
            .ok_or(crate::error::HandshakeError::UnsupportedMimicryProfile(
                mimicry_profile_id,
            ))?;

        let padding_length = buf.get_u16();
        if padding_length as usize > MAX_PADDING_SIZE {
            return Err(PacketError::InvalidPaddingSize {
                size: padding_length as usize,
                max: MAX_PADDING_SIZE,
            }
            .into());
        }

        Ok(Self {
            version,
            flags,
            payload_length,
            session_id,
            sequence_number,
            timestamp,
            mimicry_profile,
            padding_length,
        })
    }
}

/// Пакет LLP
#[derive(Debug, Clone)]
pub struct LlpPacket {
    /// Заголовок пакета
    pub header: PacketHeader,
    /// Зашифрованный payload
    pub encrypted_payload: Bytes,
    /// Случайный padding
    pub padding: Bytes,
    /// Auth tag (Poly1305)
    pub auth_tag: [u8; AUTH_TAG_SIZE],
}

impl LlpPacket {
    /// Создать новый пакет
    pub fn new(
        header: PacketHeader,
        encrypted_payload: Bytes,
        padding: Bytes,
        auth_tag: [u8; AUTH_TAG_SIZE],
    ) -> Result<Self> {
        // Валидация размеров
        if encrypted_payload.len() > MAX_PAYLOAD_SIZE {
            return Err(PacketError::PacketTooLarge {
                size: encrypted_payload.len(),
                max: MAX_PAYLOAD_SIZE,
            }
            .into());
        }

        if padding.len() > MAX_PADDING_SIZE {
            return Err(PacketError::InvalidPaddingSize {
                size: padding.len(),
                max: MAX_PADDING_SIZE,
            }
            .into());
        }

        Ok(Self {
            header,
            encrypted_payload,
            padding,
            auth_tag,
        })
    }

    /// Получить общий размер пакета
    pub fn total_size(&self) -> usize {
        HEADER_SIZE
            + self.encrypted_payload.len()
            + self.padding.len()
            + AUTH_TAG_SIZE
    }

    /// Сериализовать пакет в байты
    ///
    /// # Формат
    /// [Header][Encrypted Payload][Padding][Auth Tag]
    pub fn serialize(&self) -> Result<Bytes> {
        let total_size = self.total_size();
        if total_size > MAX_PACKET_SIZE {
            return Err(PacketError::PacketTooLarge {
                size: total_size,
                max: MAX_PACKET_SIZE,
            }
            .into());
        }

        let mut buf = BytesMut::with_capacity(total_size);

        // Сериализуем заголовок с актуальными размерами
        let mut header = self.header.clone();
        header.payload_length = self.encrypted_payload.len() as u16;
        header.padding_length = self.padding.len() as u16;
        header.serialize(&mut buf);

        // Добавляем payload, padding и auth tag
        buf.put(self.encrypted_payload.clone());
        buf.put(self.padding.clone());
        buf.put(&self.auth_tag[..]);

        Ok(buf.freeze())
    }

    /// Десериализовать пакет из байтов
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        if data.len() < MIN_PACKET_SIZE {
            return Err(PacketError::InvalidPacketSize {
                expected: MIN_PACKET_SIZE,
                actual: data.len(),
            }
            .into());
        }

        let mut buf = Bytes::copy_from_slice(data);
        let mut cursor = buf.clone();

        // Парсим заголовок
        let header = PacketHeader::deserialize(&mut cursor)?;

        // Вычисляем ожидаемый размер пакета
        let expected_size = HEADER_SIZE
            + header.payload_length as usize
            + header.padding_length as usize
            + AUTH_TAG_SIZE;

        if data.len() != expected_size {
            return Err(PacketError::InvalidPacketSize {
                expected: expected_size,
                actual: data.len(),
            }
            .into());
        }

        // Извлекаем payload
        buf.advance(HEADER_SIZE);
        let encrypted_payload = buf.split_to(header.payload_length as usize);

        // Извлекаем padding
        let padding = buf.split_to(header.padding_length as usize);

        // Извлекаем auth tag
        if buf.len() != AUTH_TAG_SIZE {
            return Err(PacketError::InvalidAuthTagSize {
                expected: AUTH_TAG_SIZE,
                actual: buf.len(),
            }
            .into());
        }

        let mut auth_tag = [0u8; AUTH_TAG_SIZE];
        auth_tag.copy_from_slice(&buf[..]);

        Ok(Self {
            header,
            encrypted_payload,
            padding,
            auth_tag,
        })
    }

    /// Проверить, является ли пакет DATA пакетом
    pub fn is_data(&self) -> bool {
        self.header.flags.contains(PacketFlags::DATA)
    }

    /// Проверить, является ли пакет CONTROL пакетом
    pub fn is_control(&self) -> bool {
        self.header.flags.contains(PacketFlags::CONTROL)
    }

    /// Проверить, является ли пакет фрагментом
    pub fn is_fragment(&self) -> bool {
        self.header.flags.contains(PacketFlags::FRAGMENT)
    }

    /// Проверить, является ли пакет последним фрагментом
    pub fn is_last_fragment(&self) -> bool {
        self.header
            .flags
            .contains(PacketFlags::FRAGMENT | PacketFlags::LAST_FRAG)
    }

    /// Проверить, является ли пакет keepalive
    pub fn is_keepalive(&self) -> bool {
        self.header.flags.contains(PacketFlags::KEEPALIVE)
    }

    /// Проверить, требуется ли rekey
    pub fn is_rekey(&self) -> bool {
        self.header.flags.contains(PacketFlags::REKEY)
    }
}

impl fmt::Display for LlpPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LlpPacket {{ session: {}, seq: {}, flags: [{}], payload: {} bytes, padding: {} bytes, profile: {} }}",
            self.header.session_id,
            self.header.sequence_number,
            self.header.flags,
            self.encrypted_payload.len(),
            self.padding.len(),
            self.header.mimicry_profile
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_flags() {
        let flags = PacketFlags::DATA | PacketFlags::FRAGMENT;
        assert!(flags.contains(PacketFlags::DATA));
        assert!(flags.contains(PacketFlags::FRAGMENT));
        assert!(!flags.contains(PacketFlags::CONTROL));

        let bits = flags.bits();
        let restored = PacketFlags::from_bits(bits).unwrap();
        assert_eq!(flags, restored);
    }

    #[test]
    fn test_mimicry_profile_conversion() {
        assert_eq!(
            MimicryProfile::from_u16(1),
            Some(MimicryProfile::VkVideo)
        );
        assert_eq!(MimicryProfile::VkVideo.to_u16(), 1);
        assert_eq!(MimicryProfile::from_u16(999), None);
    }

    #[test]
    fn test_header_serialization() {
        let header = PacketHeader::new(
            PacketFlags::DATA,
            12345,
            67890,
            MimicryProfile::VkVideo,
        );

        let mut buf = BytesMut::new();
        header.serialize(&mut buf);

        assert_eq!(buf.len(), HEADER_SIZE);

        let mut cursor = buf.clone();
        let deserialized = PacketHeader::deserialize(&mut cursor).unwrap();

        assert_eq!(deserialized.version, PROTOCOL_VERSION);
        assert_eq!(deserialized.flags, PacketFlags::DATA);
        assert_eq!(deserialized.session_id, 12345);
        assert_eq!(deserialized.sequence_number, 67890);
        assert_eq!(deserialized.mimicry_profile, MimicryProfile::VkVideo);
    }

    #[test]
    fn test_packet_serialization_deserialization() {
        let header = PacketHeader::new(
            PacketFlags::DATA | PacketFlags::ACK,
            12345,
            67890,
            MimicryProfile::RuTube,
        );

        let payload = Bytes::from_static(b"Hello, LLP!");
        let padding = Bytes::from_static(b"pad");
        let auth_tag = [0x42u8; AUTH_TAG_SIZE];

        let packet = LlpPacket::new(header, payload.clone(), padding.clone(), auth_tag)
            .unwrap();

        // Сериализация
        let serialized = packet.serialize().unwrap();

        // Десериализация
        let deserialized = LlpPacket::deserialize(&serialized).unwrap();

        // Проверка
        assert_eq!(deserialized.header.session_id, 12345);
        assert_eq!(deserialized.header.sequence_number, 67890);
        assert_eq!(
            deserialized.header.flags,
            PacketFlags::DATA | PacketFlags::ACK
        );
        assert_eq!(deserialized.encrypted_payload, payload);
        assert_eq!(deserialized.padding, padding);
        assert_eq!(deserialized.auth_tag, auth_tag);
    }

    #[test]
    fn test_packet_too_large() {
        let header = PacketHeader::new(
            PacketFlags::DATA,
            1,
            1,
            MimicryProfile::None,
        );

        let huge_payload = Bytes::from(vec![0u8; MAX_PAYLOAD_SIZE + 1]);
        let result = LlpPacket::new(
            header,
            huge_payload,
            Bytes::new(),
            [0u8; AUTH_TAG_SIZE],
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_version() {
        let mut buf = BytesMut::with_capacity(HEADER_SIZE);
        buf.put_u8(99); // Неверная версия
        buf.put_u8(PacketFlags::DATA.bits());
        buf.put_u16(0);
        buf.put_u64(0);
        buf.put_u32(0);
        buf.put_u32(0);
        buf.put_u16(0);
        buf.put_u16(0);

        let mut cursor = buf.clone();
        let result = PacketHeader::deserialize(&mut cursor);
        assert!(result.is_err());
    }

    #[test]
    fn test_packet_type_checks() {
        let mut header = PacketHeader::new(
            PacketFlags::DATA,
            1,
            1,
            MimicryProfile::None,
        );

        let packet = LlpPacket::new(
            header.clone(),
            Bytes::new(),
            Bytes::new(),
            [0u8; AUTH_TAG_SIZE],
        )
        .unwrap();

        assert!(packet.is_data());
        assert!(!packet.is_control());
        assert!(!packet.is_keepalive());

        header.flags = PacketFlags::KEEPALIVE;
        let keepalive_packet = LlpPacket::new(
            header,
            Bytes::new(),
            Bytes::new(),
            [0u8; AUTH_TAG_SIZE],
        )
        .unwrap();

        assert!(keepalive_packet.is_keepalive());
        assert!(!keepalive_packet.is_data());
    }

    #[test]
    fn test_fragment_flags() {
        let header = PacketHeader::new(
            PacketFlags::DATA | PacketFlags::FRAGMENT,
            1,
            1,
            MimicryProfile::None,
        );

        let packet = LlpPacket::new(
            header.clone(),
            Bytes::new(),
            Bytes::new(),
            [0u8; AUTH_TAG_SIZE],
        )
        .unwrap();

        assert!(packet.is_fragment());
        assert!(!packet.is_last_fragment());

        let header_last = PacketHeader::new(
            PacketFlags::DATA | PacketFlags::FRAGMENT | PacketFlags::LAST_FRAG,
            1,
            2,
            MimicryProfile::None,
        );

        let last_packet = LlpPacket::new(
            header_last,
            Bytes::new(),
            Bytes::new(),
            [0u8; AUTH_TAG_SIZE],
        )
        .unwrap();

        assert!(last_packet.is_last_fragment());
    }

    #[test]
    fn test_zero_payload_packet() {
        let header = PacketHeader::new(
            PacketFlags::KEEPALIVE,
            1,
            1,
            MimicryProfile::None,
        );

        let packet = LlpPacket::new(
            header,
            Bytes::new(),
            Bytes::new(),
            [0xAAu8; AUTH_TAG_SIZE],
        )
        .unwrap();

        let serialized = packet.serialize().unwrap();
        let deserialized = LlpPacket::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.encrypted_payload.len(), 0);
        assert_eq!(deserialized.padding.len(), 0);
        assert_eq!(deserialized.auth_tag, [0xAAu8; AUTH_TAG_SIZE]);
    }
}
