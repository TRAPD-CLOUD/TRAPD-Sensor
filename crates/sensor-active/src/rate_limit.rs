//! Das Probe-Budget.
//!
//! Jede aktive Probe — ICMP, TCP-Connect, Banner, SNMP — muss hier ein Token
//! holen. Es gibt keinen zweiten Weg ins Netz. Das ist bewusst so gebaut: die
//! Zusage "der Sensor überflutet dein Netz nicht" ist nur so viel wert wie die
//! Stelle, an der sie erzwungen wird, und eine einzige solche Stelle lässt sich
//! prüfen.
//!
//! Ein Token-Bucket, kein Fenster-Zähler: ein Zähler pro Sekunde erlaubt es,
//! das gesamte Budget in der ersten Millisekunde zu verfeuern. Genau dieses
//! Burst-Verhalten lässt einen Switch oder einen schwachen IoT-Stack stolpern.

use std::time::Duration;

use tokio::time::Instant;

pub struct RateLimiter {
    /// Tokens pro Sekunde.
    rate: f64,
    /// Maximal ansparbare Tokens.
    capacity: f64,
    tokens: f64,
    last_refill: Instant,
}

impl RateLimiter {
    /// `per_second` Probes pro Sekunde. Der Eimer fasst höchstens eine Sekunde
    /// an Vorrat — angesparte Ruhe darf nicht zu einem Ausbruch führen.
    pub fn new(per_second: u32) -> Self {
        let rate = f64::from(per_second.max(1));
        Self {
            rate,
            capacity: rate,
            tokens: rate,
            last_refill: Instant::now(),
        }
    }

    /// Wartet, bis eine Probe erlaubt ist.
    pub async fn acquire(&mut self) {
        loop {
            self.refill();
            if self.tokens >= 1.0 {
                self.tokens -= 1.0;
                return;
            }
            let missing = 1.0 - self.tokens;
            let wait = Duration::from_secs_f64((missing / self.rate).max(0.001));
            tokio::time::sleep(wait).await;
        }
    }

    /// Nimmt ein Token, wenn eines da ist — ohne zu warten.
    pub fn try_acquire(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Aktuell verfügbare Tokens (für Tests und Metriken).
    pub fn available(&mut self) -> f64 {
        self.refill();
        self.tokens
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        if elapsed <= 0.0 {
            return;
        }
        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
        self.last_refill = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn the_initial_burst_is_bounded_by_the_rate() {
        let mut limiter = RateLimiter::new(5);

        for i in 0..5 {
            assert!(limiter.try_acquire(), "token {i} should be available");
        }
        assert!(
            !limiter.try_acquire(),
            "the bucket must not hand out more than one second of budget at once"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn tokens_refill_over_time() {
        let mut limiter = RateLimiter::new(10);
        for _ in 0..10 {
            assert!(limiter.try_acquire());
        }
        assert!(!limiter.try_acquire());

        tokio::time::advance(Duration::from_millis(500)).await;
        // Nach einer halben Sekunde sind ~5 Tokens zurück.
        let mut granted = 0;
        while limiter.try_acquire() {
            granted += 1;
        }
        assert!(
            (4..=6).contains(&granted),
            "expected roughly half the budget back, got {granted}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn idle_time_does_not_accumulate_an_unbounded_burst() {
        let mut limiter = RateLimiter::new(4);
        tokio::time::advance(Duration::from_secs(3600)).await;

        let mut granted = 0;
        while limiter.try_acquire() {
            granted += 1;
        }
        assert_eq!(
            granted, 4,
            "an hour of quiet must not buy an hour's worth of probes"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn acquire_waits_instead_of_dropping_the_probe() {
        let mut limiter = RateLimiter::new(2);
        limiter.acquire().await;
        limiter.acquire().await;

        let start = Instant::now();
        limiter.acquire().await;
        assert!(
            start.elapsed() >= Duration::from_millis(400),
            "the third probe in a 2/s budget has to wait"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_zero_rate_is_treated_as_one_per_second() {
        let mut limiter = RateLimiter::new(0);
        assert!(
            limiter.try_acquire(),
            "never configure the sensor to a standstill"
        );
        assert!(!limiter.try_acquire());
    }

    /// Über längere Zeit muss sich die konfigurierte Rate einstellen. Der volle
    /// Eimer beim Start schlägt einmalig mit einer Sekunde Budget zu Buche —
    /// das ist gewollt, damit ein kleiner Sweep nicht erst warten muss.
    #[tokio::test(start_paused = true)]
    async fn sustained_rate_matches_the_configuration() {
        let mut limiter = RateLimiter::new(10);
        let mut granted = 0;

        // Zwei Sekunden simulierte Laufzeit in 20 Schritten.
        for _ in 0..20 {
            while limiter.try_acquire() {
                granted += 1;
            }
            tokio::time::advance(Duration::from_millis(100)).await;
        }

        // 10 aus dem vollen Eimer + rund 20 nachgefüllte.
        assert!(
            (28..=32).contains(&granted),
            "10/s over ~2s plus the initial bucket should be about 30, got {granted}"
        );
    }
}
