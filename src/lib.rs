use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// IP-based sliding window rate limiter.
///
/// Tracks requests per IP within a configurable time window.
/// Thread-safe via `Arc<Mutex<...>>` — clone freely across handlers.
#[derive(Clone)]
pub struct RateLimiter {
    requests: Arc<Mutex<HashMap<IpAddr, Vec<Instant>>>>,
    max_requests: usize,
    window: Duration,
}

impl RateLimiter {
    /// Create a rate limiter allowing `max_per_hour` requests per IP per hour.
    pub fn per_hour(max_per_hour: usize) -> Self {
        Self {
            requests: Arc::new(Mutex::new(HashMap::new())),
            max_requests: max_per_hour,
            window: Duration::from_secs(3600),
        }
    }

    /// Create a rate limiter with a custom window duration.
    pub fn new(max_requests: usize, window: Duration) -> Self {
        Self {
            requests: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            window,
        }
    }

    /// Check if the given IP is within rate limits and record the request.
    /// Returns `true` if allowed, `false` if rate-limited.
    pub async fn check_and_record(&self, ip: IpAddr) -> bool {
        let mut map = self.requests.lock().await;
        let now = Instant::now();

        let entries = map.entry(ip).or_default();
        entries.retain(|t| now.duration_since(*t) < self.window);

        if entries.len() >= self.max_requests {
            return false;
        }

        entries.push(now);
        true
    }
}

/// Extract client IP from the `x-forwarded-for` header (Fly.io, Cloudflare, etc.).
/// Falls back to 127.0.0.1 if no header is present.
pub fn extract_client_ip(headers: &http::HeaderMap) -> IpAddr {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
        .unwrap_or_else(|| IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn allows_within_limit() {
        let limiter = RateLimiter::per_hour(5);
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
        for _ in 0..5 {
            assert!(limiter.check_and_record(ip).await);
        }
    }

    #[tokio::test]
    async fn blocks_over_limit() {
        let limiter = RateLimiter::per_hour(3);
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
        for _ in 0..3 {
            assert!(limiter.check_and_record(ip).await);
        }
        assert!(!limiter.check_and_record(ip).await);
    }

    #[tokio::test]
    async fn independent_ips() {
        let limiter = RateLimiter::per_hour(2);
        let ip1 = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2));

        assert!(limiter.check_and_record(ip1).await);
        assert!(limiter.check_and_record(ip1).await);
        assert!(!limiter.check_and_record(ip1).await);
        assert!(limiter.check_and_record(ip2).await);
    }

    #[tokio::test]
    async fn custom_window() {
        let limiter = RateLimiter::new(100, Duration::from_secs(60));
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
        assert!(limiter.check_and_record(ip).await);
    }

    #[test]
    fn extract_ip_from_forwarded_header() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.50".parse().unwrap());
        assert_eq!(
            extract_client_ip(&headers),
            IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 50))
        );
    }

    #[test]
    fn extract_ip_multiple_ips() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.50, 10.0.0.1".parse().unwrap());
        assert_eq!(
            extract_client_ip(&headers),
            IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 50))
        );
    }

    #[test]
    fn extract_ip_fallback() {
        let headers = http::HeaderMap::new();
        assert_eq!(
            extract_client_ip(&headers),
            IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
        );
    }
}
