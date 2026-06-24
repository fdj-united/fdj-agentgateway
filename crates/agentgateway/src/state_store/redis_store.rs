//! Redis-backed [`StateStore`] backend.
//!
//! State is held in a shared Redis instance so it is pod-independent: a
//! confirmation issued on one pod is consumable on any other, and rate-limit
//! counters are global rather than per-pod. Selected at startup when `REDIS_URL`
//! is set.
//!
//! Redis primitives used:
//!   * confirmations — `SET key 1 EX <ttl>` (Phase 1) / `DEL key` returning the
//!     removed count (atomic single-use consume in Phase 2).
//!   * rate limits — pipelined `INCR key` + `EXPIRE key <window> NX` so the fixed
//!     window is armed only on the first increment and never extended.

use std::time::Duration;

use async_trait::async_trait;
use redis::AsyncCommands;
use redis::aio::ConnectionManager;

use super::{StateResult, StateStore, StateStoreError};
use crate::mcp::FailureMode;

/// `StateStore` backed by a shared Redis instance.
///
/// Holds a multiplexed [`ConnectionManager`] (cheap to clone, auto-reconnecting).
/// On a backend error the configured [`FailureMode`] decides whether the error
/// surfaces (`FailClosed`) or a safe fallback is returned (`FailOpen`).
#[derive(Clone)]
pub struct RedisStore {
	conn: ConnectionManager,
	failure_mode: FailureMode,
}

impl std::fmt::Debug for RedisStore {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("RedisStore")
			.field("failure_mode", &self.failure_mode)
			.finish_non_exhaustive()
	}
}

impl RedisStore {
	/// Connect to Redis at `url` and return a ready store. The initial connection
	/// is established eagerly so a misconfigured `REDIS_URL` fails fast at startup.
	pub async fn connect(url: &str, failure_mode: FailureMode) -> anyhow::Result<Self> {
		let client = redis::Client::open(url)?;
		let conn = ConnectionManager::new(client).await?;
		Ok(Self { conn, failure_mode })
	}

	/// Apply the failure-mode policy to a backend result: propagate under
	/// `FailClosed`, swallow in favour of `fallback` under `FailOpen`.
	fn apply<T>(&self, op: &str, res: redis::RedisResult<T>, fallback: T) -> StateResult<T> {
		match res {
			Ok(v) => Ok(v),
			Err(e) => match self.failure_mode {
				FailureMode::FailOpen => {
					tracing::warn!(error = %e, op, "redis state store error; failing open");
					Ok(fallback)
				},
				FailureMode::FailClosed => Err(StateStoreError::Backend(e.to_string())),
			},
		}
	}
}

#[async_trait]
impl StateStore for RedisStore {
	async fn put_confirmation(&self, key: &str, ttl: Duration) -> StateResult<()> {
		let mut conn = self.conn.clone();
		// EXPIRE granularity is whole seconds; never store a 0s (never-expiring) key.
		let secs = ttl.as_secs().max(1);
		let res: redis::RedisResult<()> = conn.set_ex(key, 1u8, secs).await;
		self.apply("put_confirmation", res, ())
	}

	async fn take_confirmation(&self, key: &str) -> StateResult<bool> {
		let mut conn = self.conn.clone();
		// DEL returns the number of keys removed: 1 if the sentinel existed (and had
		// not already expired), 0 otherwise. Atomic, so the consume is single-use
		// even across concurrent pods.
		let res: redis::RedisResult<i64> = conn.del(key).await;
		self.apply("take_confirmation", res, 0).map(|n| n > 0)
	}

	async fn increment_rate_limit(&self, key: &str, window: Duration) -> StateResult<u32> {
		let mut conn = self.conn.clone();
		let secs = window.as_secs().max(1);
		// INCR then arm the window TTL only if it isn't already set (NX), so the
		// window is fixed from the first call and not extended by later calls.
		let res: redis::RedisResult<(u32,)> = redis::pipe()
			.atomic()
			.incr(key, 1u32)
			.cmd("EXPIRE")
			.arg(key)
			.arg(secs)
			.arg("NX")
			.ignore()
			.query_async(&mut conn)
			.await;
		self.apply("increment_rate_limit", res, (0,)).map(|(c,)| c)
	}
}

#[cfg(test)]
mod tests {
	//! Live-Redis integration tests.
	//!
	//! These require a reachable Redis and are `#[ignore]`'d so the default test
	//! run stays hermetic. Run them with:
	//!
	//! ```sh
	//! docker run -d --rm -p 6379:6379 --name kait-redis redis:7-alpine
	//! REDIS_URL=redis://localhost:6379/0 \
	//!   cargo test --release -p agentgateway --lib state_store -- --ignored --nocapture
	//! ```

	use super::*;

	async fn test_store() -> RedisStore {
		let url =
			std::env::var("REDIS_URL").expect("set REDIS_URL to run the #[ignore]'d live-Redis tests");
		RedisStore::connect(&url, FailureMode::FailClosed)
			.await
			.expect("connect to Redis")
	}

	#[tokio::test]
	#[ignore = "requires a live Redis (REDIS_URL)"]
	async fn confirmation_roundtrip_is_single_use() {
		let store = test_store().await;
		let key = "cf:test:roundtrip|abc";
		store
			.put_confirmation(key, Duration::from_secs(60))
			.await
			.unwrap();

		assert!(
			store.take_confirmation(key).await.unwrap(),
			"first take consumes"
		);
		assert!(
			!store.take_confirmation(key).await.unwrap(),
			"second take finds nothing"
		);
	}

	#[tokio::test]
	#[ignore = "requires a live Redis (REDIS_URL)"]
	async fn take_absent_confirmation_is_false() {
		let store = test_store().await;
		assert!(
			!store
				.take_confirmation("cf:test:definitely-absent")
				.await
				.unwrap()
		);
	}

	#[tokio::test]
	#[ignore = "requires a live Redis (REDIS_URL)"]
	async fn confirmation_expires() {
		let store = test_store().await;
		let key = "cf:test:expiry|abc";
		// Minimum EXPIRE granularity is 1s.
		store
			.put_confirmation(key, Duration::from_secs(1))
			.await
			.unwrap();
		tokio::time::sleep(Duration::from_millis(1300)).await;
		assert!(
			!store.take_confirmation(key).await.unwrap(),
			"expired sentinel gone"
		);
	}

	#[tokio::test]
	#[ignore = "requires a live Redis (REDIS_URL)"]
	async fn rate_limit_increments_within_window() {
		let store = test_store().await;
		let key = "rl:test:increments";
		// Clean any residue from a prior run.
		store.take_confirmation(key).await.ok();
		let window = Duration::from_secs(60);
		assert_eq!(store.increment_rate_limit(key, window).await.unwrap(), 1);
		assert_eq!(store.increment_rate_limit(key, window).await.unwrap(), 2);
		assert_eq!(store.increment_rate_limit(key, window).await.unwrap(), 3);
	}

	#[tokio::test]
	#[ignore = "requires a live Redis (REDIS_URL)"]
	async fn rate_limit_window_resets_after_ttl() {
		let store = test_store().await;
		let key = "rl:test:reset";
		store.take_confirmation(key).await.ok();
		let window = Duration::from_secs(1);
		assert_eq!(store.increment_rate_limit(key, window).await.unwrap(), 1);
		assert_eq!(store.increment_rate_limit(key, window).await.unwrap(), 2);
		tokio::time::sleep(Duration::from_millis(1300)).await;
		// Window elapsed: counter restarts.
		assert_eq!(store.increment_rate_limit(key, window).await.unwrap(), 1);
	}
}
