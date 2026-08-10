//! Exponentielles Backoff mit Jitter.
//!
//! Der Jitter ist nicht Kosmetik: fällt ein Backend aus, kommen alle Sensoren
//! eines Tenants gleichzeitig ins Stolpern und würden ohne Streuung im
//! Gleichtakt wieder anklopfen — und das Backend beim Hochfahren gleich wieder
//! umwerfen. Gestreut wird deshalb im Bereich [50 %, 100 %] des berechneten
//! Wartewerts.

use std::time::Duration;

use rand::Rng;

#[derive(Debug, Clone)]
pub struct BackoffConfig {
    pub initial: Duration,
    pub max: Duration,
    pub multiplier: f64,
}

impl Default for BackoffConfig {
    fn default() -> Self {
        Self {
            initial: Duration::from_secs(1),
            max: Duration::from_secs(60),
            multiplier: 2.0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Backoff {
    config: BackoffConfig,
    /// Aktuelle Basis *ohne* Jitter.
    current: Duration,
    attempts: u32,
}

impl Backoff {
    pub fn new(config: BackoffConfig) -> Self {
        let current = config.initial;
        Self {
            config,
            current,
            attempts: 0,
        }
    }

    /// Nächste Wartezeit inklusive Jitter; erhöht die Basis für den Folgeaufruf.
    pub fn next_delay(&mut self) -> Duration {
        let base = self.current;
        self.attempts = self.attempts.saturating_add(1);
        self.current = Duration::from_secs_f64(
            (self.current.as_secs_f64() * self.config.multiplier)
                .min(self.config.max.as_secs_f64()),
        );
        jitter(base)
    }

    /// Nach einem erfolgreichen Versuch: zurück auf Anfang.
    pub fn reset(&mut self) {
        self.current = self.config.initial;
        self.attempts = 0;
    }

    /// Aufeinanderfolgende Fehlversuche seit dem letzten [`Self::reset`].
    pub fn attempts(&self) -> u32 {
        self.attempts
    }

    /// Übersteuert die Wartezeit — für ein `Retry-After` des Servers. Der Server
    /// weiß besser als wir, wann er wieder bereit ist.
    pub fn override_next(&mut self, delay: Duration) {
        self.current = delay.min(self.config.max);
    }
}

fn jitter(base: Duration) -> Duration {
    if base.is_zero() {
        return base;
    }
    let factor = rand::thread_rng().gen_range(0.5_f64..=1.0);
    Duration::from_secs_f64(base.as_secs_f64() * factor)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> BackoffConfig {
        BackoffConfig {
            initial: Duration::from_secs(1),
            max: Duration::from_secs(16),
            multiplier: 2.0,
        }
    }

    #[test]
    fn delays_grow_and_stay_within_the_jitter_window() {
        let mut b = Backoff::new(config());
        // Basis 1s, 2s, 4s, 8s, 16s → mit Jitter jeweils [50 %, 100 %].
        for expected_base in [1.0, 2.0, 4.0, 8.0, 16.0_f64] {
            let d = b.next_delay().as_secs_f64();
            assert!(
                d >= expected_base * 0.5 - 1e-9 && d <= expected_base + 1e-9,
                "delay {d} outside jitter window for base {expected_base}"
            );
        }
    }

    #[test]
    fn delay_is_capped_at_max() {
        let mut b = Backoff::new(config());
        for _ in 0..20 {
            let d = b.next_delay();
            assert!(d <= Duration::from_secs(16), "delay {d:?} exceeded the cap");
        }
    }

    #[test]
    fn reset_returns_to_the_initial_delay() {
        let mut b = Backoff::new(config());
        for _ in 0..5 {
            b.next_delay();
        }
        assert_eq!(b.attempts(), 5);

        b.reset();
        assert_eq!(b.attempts(), 0);
        let d = b.next_delay().as_secs_f64();
        assert!(d <= 1.0, "after reset the delay must start over, got {d}");
    }

    #[test]
    fn server_retry_after_overrides_the_schedule() {
        let mut b = Backoff::new(config());
        for _ in 0..5 {
            b.next_delay();
        }
        b.override_next(Duration::from_secs(3));
        let d = b.next_delay().as_secs_f64();
        assert!((1.5..=3.0).contains(&d), "expected ~3s window, got {d}");
    }

    #[test]
    fn retry_after_beyond_the_cap_is_clamped() {
        let mut b = Backoff::new(config());
        b.override_next(Duration::from_secs(3600));
        assert!(b.next_delay() <= Duration::from_secs(16));
    }

    #[test]
    fn jitter_actually_varies() {
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..50 {
            let mut b = Backoff::new(BackoffConfig {
                initial: Duration::from_secs(10),
                max: Duration::from_secs(60),
                multiplier: 2.0,
            });
            seen.insert(b.next_delay().as_millis());
        }
        assert!(
            seen.len() > 1,
            "all sensors would retry in lockstep without jitter"
        );
    }
}
