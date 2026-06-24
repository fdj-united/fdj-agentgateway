//! In-process [`StateStore`] backend.
//!
//! This preserves the gateway's original per-pod behaviour: state lives in this
//! process's memory and is invisible to other pods. It is the default backend
//! and is used whenever `REDIS_URL` is unset. Never errors.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;

use super::{StateResult, StateStore};

/// Fixed-window counter for a single rate-limit key.
#[derive(Debug)]
struct RateWindow {
	count: u32,
	started_at: Instant,
}

/// `StateStore` that keeps all state in process memory behind mutexes.
#[derive(Debug, Default)]
pub struct InMemoryStore {
	/// Confirmation sentinels: key -> expiry instant.
	confirmations: Mutex<HashMap<String, Instant>>,
	/// Rate-limit counters: key -> current window.
	rate_limits: Mutex<HashMap<String, RateWindow>>,
}

impl InMemoryStore {
	pub fn new() -> Self {
		Self::default()
	}
}

#[async_trait]
impl StateStore for InMemoryStore {
	async fn put_confirmation(&self, key: &str, ttl: Duration) -> StateResult<()> {
		let expires_at = Instant::now() + ttl;
		self
			.confirmations
			.lock()
			.expect("poisoned")
			.insert(key.to_string(), expires_at);
		Ok(())
	}

	async fn take_confirmation(&self, key: &str) -> StateResult<bool> {
		let mut map = self.confirmations.lock().expect("poisoned");
		// Single-use: remove on lookup regardless of outcome. An expired sentinel
		// is treated as absent (returns false) but is still purged.
		match map.remove(key) {
			Some(expires_at) => Ok(Instant::now() <= expires_at),
			None => Ok(false),
		}
	}

	async fn increment_rate_limit(&self, key: &str, window: Duration) -> StateResult<u32> {
		let mut map = self.rate_limits.lock().expect("poisoned");
		let now = Instant::now();
		let entry = map.entry(key.to_string()).or_insert(RateWindow {
			count: 0,
			started_at: now,
		});
		if now.duration_since(entry.started_at) >= window {
			// Window elapsed: restart it.
			entry.count = 1;
			entry.started_at = now;
		} else {
			entry.count += 1;
		}
		Ok(entry.count)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[tokio::test]
	async fn confirmation_is_single_use() {
		let store = InMemoryStore::new();
		store
			.put_confirmation("cf:s1:tool|abc", Duration::from_secs(60))
			.await
			.unwrap();

		// First take consumes it (Phase 2).
		assert!(store.take_confirmation("cf:s1:tool|abc").await.unwrap());
		// Second take finds nothing — cannot be replayed.
		assert!(!store.take_confirmation("cf:s1:tool|abc").await.unwrap());
	}

	#[tokio::test]
	async fn take_absent_confirmation_is_false() {
		let store = InMemoryStore::new();
		assert!(!store.take_confirmation("cf:s1:missing").await.unwrap());
	}

	#[tokio::test]
	async fn expired_confirmation_is_not_matched() {
		let store = InMemoryStore::new();
		store
			.put_confirmation("cf:s1:tool|abc", Duration::from_millis(10))
			.await
			.unwrap();
		tokio::time::sleep(Duration::from_millis(30)).await;
		// Past its TTL: treated as no pending confirmation.
		assert!(!store.take_confirmation("cf:s1:tool|abc").await.unwrap());
	}

	#[tokio::test]
	async fn rate_limit_counts_within_window_then_resets() {
		let store = InMemoryStore::new();
		let window = Duration::from_millis(40);

		assert_eq!(
			store.increment_rate_limit("rl:s1:t", window).await.unwrap(),
			1
		);
		assert_eq!(
			store.increment_rate_limit("rl:s1:t", window).await.unwrap(),
			2
		);
		assert_eq!(
			store.increment_rate_limit("rl:s1:t", window).await.unwrap(),
			3
		);

		// After the window elapses the counter restarts at 1.
		tokio::time::sleep(Duration::from_millis(60)).await;
		assert_eq!(
			store.increment_rate_limit("rl:s1:t", window).await.unwrap(),
			1
		);
	}

	#[tokio::test]
	async fn rate_limit_keys_are_independent() {
		let store = InMemoryStore::new();
		let window = Duration::from_secs(60);
		assert_eq!(
			store.increment_rate_limit("rl:s1:a", window).await.unwrap(),
			1
		);
		assert_eq!(
			store.increment_rate_limit("rl:s1:a", window).await.unwrap(),
			2
		);
		// Different key is unaffected.
		assert_eq!(
			store.increment_rate_limit("rl:s1:b", window).await.unwrap(),
			1
		);
	}
}
