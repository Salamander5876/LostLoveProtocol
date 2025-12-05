//! Селективный DPI bypass для заблокированных в РФ ресурсов
//!
//! Этот модуль определяет какие домены требуют DPI bypass и применяет
//! соответствующие техники обхода блокировок.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::debug;

/// Список доменов, заблокированных в РФ
const BLOCKED_DOMAINS: &[&str] = &[
    // Социальные сети
    "facebook.com",
    "www.facebook.com",
    "instagram.com",
    "www.instagram.com",
    "twitter.com",
    "x.com",
    "www.twitter.com",
    "www.x.com",

    // Видео платформы
    "youtube.com",
    "www.youtube.com",
    "youtu.be",
    "googlevideo.com",

    // Мессенджеры
    "t.me",
    "telegram.org",
    "web.telegram.org",

    // Новостные ресурсы
    "meduza.io",
    "zona.media",
    "novayagazeta.ru",

    // Другие сервисы
    "discord.com",
    "linkedin.com",
    "medium.com",
];

/// Менеджер селективного DPI bypass
pub struct DpiBypassManager {
    /// Множество заблокированных доменов (для быстрого поиска)
    blocked_domains: HashSet<String>,
    /// IP адреса, которые требуют bypass
    bypassed_ips: Arc<RwLock<HashSet<IpAddr>>>,
}

impl DpiBypassManager {
    /// Создать новый менеджер
    pub fn new() -> Self {
        let mut blocked_domains = HashSet::new();
        for domain in BLOCKED_DOMAINS {
            blocked_domains.insert(domain.to_string());
        }

        Self {
            blocked_domains,
            bypassed_ips: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Проверить, требуется ли DPI bypass для данного домена
    pub fn needs_bypass(&self, domain: &str) -> bool {
        // Проверяем точное совпадение
        if self.blocked_domains.contains(domain) {
            return true;
        }

        // Проверяем поддомены (например, api.instagram.com)
        for blocked in &self.blocked_domains {
            if domain.ends_with(&format!(".{}", blocked)) {
                return true;
            }
        }

        false
    }

    /// Добавить IP в список bypass (после DNS резолва заблокированного домена)
    pub async fn add_bypassed_ip(&self, ip: IpAddr) {
        let mut ips = self.bypassed_ips.write().await;
        if ips.insert(ip) {
            debug!("Добавлен IP {} в список DPI bypass", ip);
        }
    }

    /// Проверить, требуется ли DPI bypass для IP
    pub async fn ip_needs_bypass(&self, ip: IpAddr) -> bool {
        let ips = self.bypassed_ips.read().await;
        ips.contains(&ip)
    }

    /// Применить DPI bypass к IP пакету
    pub fn apply_bypass(&self, packet: &mut [u8]) -> bool {
        // TODO: Реализовать техники обхода:
        // 1. Фрагментация TCP пакетов
        // 2. TTL манипуляции
        // 3. TCP сегментация
        // 4. SNI фрагментация для TLS handshake

        // Пока просто возвращаем пакет без изменений
        // Реализация будет добавлена после базового тестирования
        debug!("DPI bypass применён к пакету размером {} байт", packet.len());
        true
    }
}

impl Default for DpiBypassManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blocked_domains() {
        let manager = DpiBypassManager::new();

        // Заблокированные домены
        assert!(manager.needs_bypass("youtube.com"));
        assert!(manager.needs_bypass("instagram.com"));
        assert!(manager.needs_bypass("facebook.com"));

        // Поддомены
        assert!(manager.needs_bypass("www.youtube.com"));
        assert!(manager.needs_bypass("api.instagram.com"));

        // Незаблокированные
        assert!(!manager.needs_bypass("google.com"));
        assert!(!manager.needs_bypass("yandex.ru"));
        assert!(!manager.needs_bypass("vk.com"));
    }
}
