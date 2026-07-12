use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub struct ResourceControl {
    max_concurrent_scans: usize,
    current_scans: Arc<Mutex<usize>>,
    rate_limit: usize,
    rate_limit_window: Duration,
    request_timestamps: Arc<Mutex<Vec<Instant>>>,
}

impl ResourceControl {
    pub fn new(max_concurrent_scans: usize, rate_limit: usize, rate_limit_window_seconds: u64) -> Self {
        ResourceControl {
            max_concurrent_scans,
            current_scans: Arc::new(Mutex::new(0)),
            rate_limit,
            rate_limit_window: Duration::from_secs(rate_limit_window_seconds),
            request_timestamps: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn try_acquire_scan(&self) -> bool {
        let mut current = self.current_scans.lock().unwrap();
        if *current < self.max_concurrent_scans {
            *current += 1;
            true
        } else {
            false
        }
    }

    pub fn release_scan(&self) {
        let mut current = self.current_scans.lock().unwrap();
        if *current > 0 {
            *current -= 1;
        }
    }

    pub fn try_acquire_request(&self) -> bool {
        let now = Instant::now();
        let mut timestamps = self.request_timestamps.lock().unwrap();
        
        timestamps.retain(|t| now.duration_since(*t) <= self.rate_limit_window);
        
        if timestamps.len() < self.rate_limit {
            timestamps.push(now);
            true
        } else {
            false
        }
    }

    pub fn get_current_scans(&self) -> usize {
        *self.current_scans.lock().unwrap()
    }

    pub fn get_max_concurrent_scans(&self) -> usize {
        self.max_concurrent_scans
    }

    pub fn get_rate_limit_status(&self) -> (usize, usize) {
        let now = Instant::now();
        let mut timestamps = self.request_timestamps.lock().unwrap();
        timestamps.retain(|t| now.duration_since(*t) <= self.rate_limit_window);
        (timestamps.len(), self.rate_limit)
    }
}

impl Default for ResourceControl {
    fn default() -> Self {
        ResourceControl::new(10, 100, 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acquire_scan() {
        let control = ResourceControl::new(2, 100, 60);
        
        assert!(control.try_acquire_scan());
        assert!(control.try_acquire_scan());
        assert!(!control.try_acquire_scan());
        
        control.release_scan();
        assert!(control.try_acquire_scan());
    }

    #[test]
    fn test_rate_limit() {
        let control = ResourceControl::new(10, 3, 60);
        
        assert!(control.try_acquire_request());
        assert!(control.try_acquire_request());
        assert!(control.try_acquire_request());
        assert!(!control.try_acquire_request());
    }
}
