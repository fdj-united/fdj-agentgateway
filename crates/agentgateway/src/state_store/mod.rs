//! Pluggable backing store for the gateway's per-session ephemeral MCP state.
//!
//! Two pieces of state were historically held in each pod's process memory:
//!
//!   * **`mcpConfirmation`** pending approvals — single-use sentinels, keyed by
//!     `(session, tool, args-hash)`, that gate the two-phase confirmation flow.
//!   * **`mcpRateLimit`** counters — fixed-window per-tool call counts.
//!
//! Keeping this state in-process is correct for a single pod but breaks when the
//! gateway scales to `replicas > 1`: a confirmation issued on pod A is invisible
//! to pod B (re-prompt), and each pod under-counts rate limits in isolation
//! (`N×` inflation). Externalising it behind [`StateStore`] lets a shared backend
//! (Redis) make the state pod-independent.
//!
//! [`InMemoryStore`] is the default and preserves the prior per-pod behaviour.
//! [`RedisStore`] is selected at startup when `REDIS_URL` is set.

mod in_memory;
mod redis_store;

use std::time::Duration;

use async_trait::async_trait;

pub use in_memory::InMemoryStore;
pub use redis_store::RedisStore;

/// Result alias for state-store operations.
pub type StateResult<T> = Result<T, StateStoreError>;

/// Error returned by a [`StateStore`] backend when an operation cannot complete.
///
/// Whether this surfaces to the caller or is swallowed in favour of a fallback
/// is governed by the backend's [`FailureMode`](crate::mcp::FailureMode):
/// `FailClosed` propagates the error, `FailOpen` returns a safe fallback instead.
#[derive(Debug, thiserror::Error)]
pub enum StateStoreError {
	#[error("state store backend error: {0}")]
	Backend(String),
}

/// Backing store for per-session ephemeral MCP state (confirmations + rate limits).
///
/// Implementations must be safe to share across tasks and session clones
/// (`Send + Sync`, used behind `Arc<dyn StateStore>`).
#[async_trait]
pub trait StateStore: Send + Sync + std::fmt::Debug {
	/// Store a single-use confirmation sentinel under `key`, expiring after `ttl`.
	///
	/// This is **Phase 1** of the two-phase confirmation flow: the call has been
	/// intercepted and the user must approve before it is replayed.
	async fn put_confirmation(&self, key: &str, ttl: Duration) -> StateResult<()>;

	/// Atomically consume the confirmation sentinel at `key`.
	///
	/// Returns `true` when a non-expired sentinel existed — i.e. **Phase 2**: the
	/// LLM re-issued the identical call after the user approved, so it should now
	/// be forwarded upstream. Returns `false` when nothing is pending (or it has
	/// expired), in which case the caller treats the call as a fresh Phase 1.
	///
	/// The consume is single-use: a `true` result removes the sentinel so the same
	/// approval cannot be replayed twice (even across pods).
	async fn take_confirmation(&self, key: &str) -> StateResult<bool>;

	/// Increment the fixed-window rate-limit counter at `key`, returning the
	/// post-increment count.
	///
	/// The first increment in a window creates the counter and arms its `window`
	/// TTL; subsequent increments within the window bump the count. Once the window
	/// elapses the counter is gone and the next increment restarts at `1`.
	async fn increment_rate_limit(&self, key: &str, window: Duration) -> StateResult<u32>;
}
