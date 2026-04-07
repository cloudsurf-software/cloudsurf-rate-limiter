use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
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

/// Extract client IP, only trusting `x-forwarded-for` when the immediate peer
/// is a known proxy listed in the `TRUSTED_PROXY_IPS` environment variable
/// (comma-separated, e.g. "172.17.0.1,10.0.0.1").
///
/// When no trusted proxies are configured, or the peer is not trusted, the
/// socket peer address is returned directly — preventing clients from spoofing
/// their IP via the forwarded header.
pub fn extract_client_ip(headers: &http::HeaderMap, peer_addr: Option<SocketAddr>) -> IpAddr {
    let trusted_proxies = std::env::var("TRUSTED_PROXY_IPS").unwrap_or_default();

    if !trusted_proxies.is_empty() {
        if let Some(peer) = peer_addr {
            let peer_ip = peer.ip().to_string();
            let trusted: Vec<&str> = trusted_proxies.split(',').map(|s| s.trim()).collect();

            if trusted.contains(&peer_ip.as_str()) {
                if let Some(forwarded) = headers.get("x-forwarded-for") {
                    if let Ok(value) = forwarded.to_str() {
                        let ips: Vec<&str> = value.split(',').map(|s| s.trim()).collect();
                        if let Some(client_ip) = ips.first() {
                            if let Ok(parsed) = client_ip.parse::<IpAddr>() {
                                return parsed;
                            }
                        }
                    }
                }
            }
        }
    }

    // Default: use actual socket peer address
    peer_addr
        .map(|a| a.ip())
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

    /// Helper: set TRUSTED_PROXY_IPS for a test, returning a guard that
    /// restores the previous value on drop.
    struct EnvGuard {
        key: &'static str,
        prev: Option<String>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let prev = std::env::var(key).ok();
            // SAFETY: tests run with --test-threads=1 or are independent of
            // each other with respect to this env var due to guard scoping.
            unsafe { std::env::set_var(key, value) };
            Self { key, prev }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            // SAFETY: see EnvGuard::set
            unsafe {
                match &self.prev {
                    Some(v) => std::env::set_var(self.key, v),
                    None => std::env::remove_var(self.key),
                }
            }
        }
    }

    fn sock(ip: &str) -> Option<SocketAddr> {
        Some(SocketAddr::new(ip.parse().unwrap(), 12345))
    }

    // --- Existing tests, updated for new signature ---

    #[test]
    fn extract_ip_from_forwarded_header_trusted_peer() {
        let _g = EnvGuard::set("TRUSTED_PROXY_IPS", "172.17.0.1");
        let mut headers = http::HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.50".parse().unwrap());
        assert_eq!(
            extract_client_ip(&headers, sock("172.17.0.1")),
            IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 50))
        );
    }

    #[test]
    fn extract_ip_multiple_ips_trusted_peer() {
        let _g = EnvGuard::set("TRUSTED_PROXY_IPS", "172.17.0.1");
        let mut headers = http::HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.50, 10.0.0.1".parse().unwrap());
        assert_eq!(
            extract_client_ip(&headers, sock("172.17.0.1")),
            IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 50))
        );
    }

    #[test]
    fn extract_ip_fallback_no_peer() {
        let _g = EnvGuard::set("TRUSTED_PROXY_IPS", "");
        let headers = http::HeaderMap::new();
        assert_eq!(
            extract_client_ip(&headers, None),
            IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
        );
    }

    // --- New security tests ---

    #[test]
    fn untrusted_peer_ignores_forwarded_header() {
        let _g = EnvGuard::set("TRUSTED_PROXY_IPS", "172.17.0.1");
        let mut headers = http::HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.50".parse().unwrap());
        // Peer 10.99.99.99 is NOT in the trusted list, so the forwarded
        // header must be ignored and the peer address used instead.
        assert_eq!(
            extract_client_ip(&headers, sock("10.99.99.99")),
            IpAddr::V4(std::net::Ipv4Addr::new(10, 99, 99, 99))
        );
    }

    #[test]
    fn trusted_peer_uses_forwarded_header() {
        let _g = EnvGuard::set("TRUSTED_PROXY_IPS", "172.17.0.1, 10.0.0.1");
        let mut headers = http::HeaderMap::new();
        headers.insert("x-forwarded-for", "198.51.100.22".parse().unwrap());
        assert_eq!(
            extract_client_ip(&headers, sock("10.0.0.1")),
            IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 22))
        );
    }

    #[test]
    fn no_trusted_proxies_uses_peer_addr() {
        let _g = EnvGuard::set("TRUSTED_PROXY_IPS", "");
        let mut headers = http::HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.50".parse().unwrap());
        // Even though the header is present, no trusted proxies are configured,
        // so the peer address must be returned.
        assert_eq!(
            extract_client_ip(&headers, sock("192.168.1.5")),
            IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 5))
        );
    }

    #[test]
    fn trusted_proxy_env_unset_uses_peer_addr() {
        // Ensure the env var is completely absent
        let _g = EnvGuard::set("TRUSTED_PROXY_IPS", "");
        // SAFETY: see EnvGuard::set
        unsafe { std::env::remove_var("TRUSTED_PROXY_IPS") };
        let mut headers = http::HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.50".parse().unwrap());
        assert_eq!(
            extract_client_ip(&headers, sock("192.168.1.5")),
            IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 5))
        );
    }

    #[test]
    fn trusted_peer_no_forwarded_header_uses_peer_addr() {
        let _g = EnvGuard::set("TRUSTED_PROXY_IPS", "172.17.0.1");
        let headers = http::HeaderMap::new();
        // Trusted peer but no forwarded header — fall back to peer address.
        assert_eq!(
            extract_client_ip(&headers, sock("172.17.0.1")),
            IpAddr::V4(std::net::Ipv4Addr::new(172, 17, 0, 1))
        );
    }
}
