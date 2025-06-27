// rusty-jsonrpc/src/rate_limiter.rs

use std::collections::HashMap;
use std::time::{Instant, Duration};
use std::net::SocketAddr;

// Constants for rate limiting
const MAX_REQUESTS_PER_SECOND_PER_IP: u32 = 50; // Max requests per IP per second
const RATE_LIMIT_WINDOW_SECONDS: u64 = 1;      // Window for rate limiting in seconds

pub struct RateLimiter {
    // Tracks requests per IP address
    requests: HashMap<SocketAddr, (u32, Instant)>, // (count, last_reset_time)
}

impl RateLimiter {
    pub fn new() -> Self {
        RateLimiter { requests: HashMap::new() }
    }

    /// Checks if a request from the given IP address is allowed by the rate limiter.
    /// Returns `true` if allowed, `false` otherwise.
    /// This function also updates the request count and handles window resets.
    pub fn allow(&mut self, addr: SocketAddr) -> bool {
        let now = Instant::now();
        let (count, last_reset) = self.requests.entry(addr).or_insert((0, now));

        // If the window has passed, reset the count
        if now.duration_since(*last_reset) >= Duration::from_secs(RATE_LIMIT_WINDOW_SECONDS) {
            *count = 0;
            *last_reset = now;
        }

        // Check if the current request is within the limit
        if *count < MAX_REQUESTS_PER_SECOND_PER_IP {
            *count += 1;
            true
        } else {
            false
        }
    }
} 