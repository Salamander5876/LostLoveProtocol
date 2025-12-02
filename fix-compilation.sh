#!/bin/bash
# Скрипт для исправления ошибок компиляции
# Использование: bash fix-compilation.sh

echo "Применение исправлений компиляции..."

# Исправление packet.rs
sed -i 's/PacketError::InvalidAuthTagSize {/PacketError::InsufficientData {/' crates/llp-core/src/packet.rs
sed -i 's/expected: AUTH_TAG_SIZE,/required: AUTH_TAG_SIZE,/' crates/llp-core/src/packet.rs
sed -i 's/actual: buf.len(),/available: buf.len(),/' crates/llp-core/src/packet.rs

# Исправление handshake.rs - удаление неиспользуемого импорта
sed -i '/use std::time::Duration;/d' crates/llp-core/src/handshake.rs

# Исправление session.rs - удаление неиспользуемых импортов
sed -i 's/use crate::packet::{LlpPacket, MimicryProfile, PacketFlags};/use crate::packet::MimicryProfile;/' crates/llp-core/src/session.rs

echo "✓ Исправления применены"
echo "Теперь запустите: cargo build --release -p llp-server"
