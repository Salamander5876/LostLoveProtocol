//! Профили timing для имитации паттернов трафика

use rand::Rng;
use std::time::Duration;

/// Профиль timing для различных типов трафика
#[derive(Debug, Clone)]
pub struct TimingProfile {
    /// Минимальная задержка между пакетами (мс)
    min_delay_ms: u64,
    /// Максимальная задержка между пакетами (мс)
    max_delay_ms: u64,
    /// Вероятность burst (0.0 - 1.0)
    burst_probability: f64,
    /// Размер burst (количество пакетов)
    burst_size: usize,
}

impl TimingProfile {
    /// Профиль для видеостриминга (burst паттерн)
    pub fn video_streaming() -> Self {
        Self {
            min_delay_ms: 10,
            max_delay_ms: 100,
            burst_probability: 0.7,
            burst_size: 5,
        }
    }

    /// Профиль для аудиостриминга (steady паттерн)
    pub fn audio_streaming() -> Self {
        Self {
            min_delay_ms: 50,
            max_delay_ms: 200,
            burst_probability: 0.3,
            burst_size: 2,
        }
    }

    /// Профиль для веб-браузинга (смешанный паттерн)
    pub fn web_browsing() -> Self {
        Self {
            min_delay_ms: 20,
            max_delay_ms: 500,
            burst_probability: 0.5,
            burst_size: 3,
        }
    }

    /// Получить следующую задержку
    pub fn next_delay<R: Rng>(&self, rng: &mut R) -> Duration {
        let is_burst = rng.gen_bool(self.burst_probability);

        let delay_ms = if is_burst {
            // Во время burst минимальная задержка
            rng.gen_range(self.min_delay_ms..self.min_delay_ms + 20)
        } else {
            // Обычная задержка
            rng.gen_range(self.min_delay_ms..self.max_delay_ms)
        };

        Duration::from_millis(delay_ms)
    }

    /// Получить размер burst
    pub fn burst_size(&self) -> usize {
        self.burst_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::ThreadRng;

    #[test]
    fn test_video_streaming_timing() {
        let profile = TimingProfile::video_streaming();
        let mut rng = rand::thread_rng();

        for _ in 0..100 {
            let delay = profile.next_delay(&mut rng);
            assert!(delay.as_millis() >= profile.min_delay_ms as u128);
            assert!(delay.as_millis() <= profile.max_delay_ms as u128);
        }
    }

    #[test]
    fn test_audio_streaming_timing() {
        let profile = TimingProfile::audio_streaming();
        let mut rng = rand::thread_rng();

        let delay = profile.next_delay(&mut rng);
        assert!(delay.as_millis() >= profile.min_delay_ms as u128);
    }
}
