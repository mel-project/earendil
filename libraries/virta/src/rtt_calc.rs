use std::time::{Duration, Instant};

pub struct RttCalculator {
    estimated_rtt: Duration,
    dev_rtt: Duration,
    min_rtt: Duration,
    min_rtt_time: Instant,
    rtt_time: Instant,
}

impl Default for RttCalculator {
    fn default() -> Self {
        RttCalculator {
            estimated_rtt: Duration::from_secs(1),
            dev_rtt: Duration::from_secs(0),
            min_rtt: Duration::from_secs(1),
            min_rtt_time: Instant::now(),
            rtt_time: Instant::now(),
        }
    }
}

impl RttCalculator {
    pub fn record_sample(&mut self, sample: Duration) {
        let alpha: f64 = 0.125;
        let beta: f64 = 0.25;
        let now = Instant::now();

        // Update minimum RTT
        if sample < self.min_rtt || now.saturating_duration_since(self.min_rtt_time).as_secs() > 30
        {
            self.min_rtt = sample;
            self.min_rtt_time = now;
        }
        if now.saturating_duration_since(self.rtt_time) > self.estimated_rtt {
            // Update EstimatedRTT and DevRTT
            self.estimated_rtt = Duration::from_secs_f64(
                (1.0 - alpha) * self.estimated_rtt.as_secs_f64() + alpha * sample.as_secs_f64(),
            );
            self.dev_rtt = Duration::from_secs_f64(
                (1.0 - beta) * self.dev_rtt.as_secs_f64()
                    + beta * (sample.as_secs_f64() - self.estimated_rtt.as_secs_f64()).abs(),
            );
            self.rtt_time = now;
        }
    }

    pub fn rto(&self) -> Duration {
        (self.estimated_rtt + Duration::from_secs_f64(4.0 * self.dev_rtt.as_secs_f64()))
            + Duration::from_millis(250)
    }

    pub fn min_rtt(&self) -> Duration {
        self.min_rtt
    }
}

pub struct BwCalculator {
    delivered: u64,
    delivered_time: Instant,

    // delivery_max_filter: MinQueue<Reverse<(OrderedFloat<f64>, Instant)>>,
    max_speed: f64,
    max_speed_time: Instant,
}

impl Default for BwCalculator {
    fn default() -> Self {
        Self {
            delivered: 0,
            delivered_time: Instant::now(),
            max_speed: 0.0,
            max_speed_time: Instant::now(),
        }
    }
}

impl BwCalculator {
    /// On ack
    pub fn on_ack(&mut self, packet_delivered: u64, packet_delivered_time: Instant) {
        let now = Instant::now();
        self.delivered += 1;
        self.delivered_time = now;
        let delivery_rate = (self.delivered - packet_delivered) as f64
            / (self.delivered_time - packet_delivered_time).as_secs_f64();
        if delivery_rate > self.max_speed
            || now.saturating_duration_since(self.max_speed_time).as_secs() > 10
        {
            self.max_speed = delivery_rate;
            self.max_speed_time = now;
        }
        log::trace!("current rate is {}", self.delivery_rate());
    }

    /// Gets the current delivery rate
    pub fn delivery_rate(&self) -> f64 {
        self.max_speed
    }

    /// Gets the current delivered packets
    pub fn delivered(&self) -> u64 {
        self.delivered
    }

    /// Gets the current delivered time
    pub fn delivered_time(&self) -> Instant {
        self.delivered_time
    }
}
