use std::time::Duration;

use ::cel::Value;
use ::cel::objects::{KeyRef, MapValue};
use serde::{Deserialize, Serialize};
use vector_map::VecMap;

use crate::cel::ContextBuilder;
use crate::http::authorization::{RuleSet, RuleSets};
use crate::*;

#[apply(schema!)]
pub struct McpAuthorization(RuleSet);

impl McpAuthorization {
	pub fn new(rule_set: RuleSet) -> Self {
		Self(rule_set)
	}

	pub fn into_inner(self) -> RuleSet {
		self.0
	}
}

pub struct CelExecWrapper(::http::Request<()>);

impl CelExecWrapper {
	pub fn new(req: ::http::Request<()>) -> CelExecWrapper {
		CelExecWrapper(req)
	}
}
#[derive(Clone, Debug)]
pub struct McpAuthorizationSet(RuleSets);

/// Configuration for two-phase tool-call confirmation.
/// When a tool call matches the CEL rules, the gateway intercepts it, returns a
/// preview to the LLM, and only forwards the actual call after the user confirms.
#[apply(schema!)]
pub struct McpConfirmation {
	#[serde(flatten)]
	pub rules: RuleSet,
	/// Seconds the pending approval stays valid. Defaults to 120.
	#[serde(rename = "ttlSeconds", default)]
	pub ttl_seconds: Option<u64>,
}

impl McpConfirmation {
	pub fn into_parts(self) -> (RuleSet, Option<u64>) {
		(self.rules, self.ttl_seconds)
	}
}

/// Runtime collection of confirmation rules, built from one or more
/// [`McpConfirmation`] policy entries.
#[derive(Clone, Debug)]
pub struct McpConfirmationSet {
	rules: RuleSets,
	/// How long a pending approval remains valid before expiring.
	pub ttl: Duration,
}

impl McpConfirmationSet {
	pub fn new(rules: RuleSets, ttl: Duration) -> Self {
		Self { rules, ttl }
	}

	/// Returns `true` when this tool call should go through two-phase confirmation.
	pub fn requires_confirmation(&self, res: &ResourceType, cel: &CelExecWrapper) -> bool {
		// Empty rule set → no tools need confirmation.
		if self.rules.is_empty() {
			return false;
		}
		let mcp = crate::mcp::MCPInfo::from(res);
		let exec = crate::cel::Executor::new_mcp_request(&cel.0, &mcp);
		self.rules.validate(&exec)
	}

	pub fn register(&self, cel: &mut ContextBuilder) {
		self.rules.register(cel);
	}
}

/// Configuration for per-session tool-call rate limiting.
/// Tools matching the CEL rules are counted per session; once `max_calls` is
/// reached within `window_seconds` the gateway returns an error response.
#[apply(schema!)]
pub struct McpRateLimit {
	#[serde(flatten)]
	pub rules: RuleSet,
	/// Maximum number of matching tool calls allowed within the window.
	#[serde(rename = "maxCalls")]
	pub max_calls: u32,
	/// Duration of the sliding window in seconds.
	#[serde(rename = "windowSeconds")]
	pub window_seconds: u64,
}

impl McpRateLimit {
	pub fn into_parts(self) -> (RuleSet, u32, u64) {
		(self.rules, self.max_calls, self.window_seconds)
	}
}

/// Runtime rate-limit policy, built from one or more [`McpRateLimit`] entries.
#[derive(Clone, Debug)]
pub struct McpRateLimitSet {
	rules: RuleSets,
	pub max_calls: u32,
	pub window: Duration,
}

impl McpRateLimitSet {
	pub fn new(rules: RuleSets, max_calls: u32, window: Duration) -> Self {
		Self { rules, max_calls, window }
	}

	/// Returns `true` when this tool call should be counted against the rate limit.
	pub fn is_limited(&self, res: &ResourceType, cel: &CelExecWrapper) -> bool {
		if self.rules.is_empty() {
			return false;
		}
		let mcp = crate::mcp::MCPInfo::from(res);
		let exec = crate::cel::Executor::new_mcp_request(&cel.0, &mcp);
		self.rules.validate(&exec)
	}

	pub fn register(&self, cel: &mut ContextBuilder) {
		self.rules.register(cel);
	}
}

impl Default for McpRateLimitSet {
	fn default() -> Self {
		Self {
			rules: RuleSets::from(Vec::new()),
			max_calls: u32::MAX,
			window: Duration::from_secs(60),
		}
	}
}

impl Default for McpConfirmationSet {
	fn default() -> Self {
		Self {
			rules: RuleSets::from(Vec::new()),
			ttl: Duration::from_secs(120),
		}
	}
}

impl McpAuthorizationSet {
	pub fn new(rs: RuleSets) -> Self {
		Self(rs)
	}
	pub fn validate(&self, res: &ResourceType, cel: &CelExecWrapper) -> bool {
		tracing::debug!("Checking RBAC for resource: {:?}", res);
		let mcp = crate::mcp::MCPInfo::from(res);
		let exec = crate::cel::Executor::new_mcp_request(&cel.0, &mcp);
		self.0.validate(&exec)
	}

	pub fn register(&self, cel: &mut ContextBuilder) {
		self.0.register(cel);
	}
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub enum ResourceType {
	/// The tool being accessed
	Tool(ResourceId),
	/// The prompt being accessed
	Prompt(ResourceId),
	/// The resource being accessed
	Resource(ResourceId),
}

impl cel::DynamicType for ResourceType {
	fn materialize(&self) -> Value<'_> {
		let (n, t) = match self {
			ResourceType::Tool(t) => ("tool", t),
			ResourceType::Prompt(t) => ("prompt", t),
			ResourceType::Resource(t) => ("resource", t),
		};
		Value::Map(MapValue::Borrow(VecMap::from_iter([(
			KeyRef::String(n.into()),
			t.materialize(),
		)])))
	}

	fn field(&self, field: &str) -> Option<Value<'_>> {
		match (self, field) {
			(ResourceType::Tool(t), "tool") => Some(t.materialize()),
			(ResourceType::Prompt(t), "prompt") => Some(t.materialize()),
			(ResourceType::Resource(t), "resource") => Some(t.materialize()),
			_ => None,
		}
	}
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, ::cel::DynamicType)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct ResourceId {
	#[serde(default)]
	/// The target of the resource
	target: String,
	#[serde(rename = "name", default)]
	/// The name of the resource
	id: String,
}

impl ResourceId {
	pub fn new(target: String, id: String) -> Self {
		Self { target, id }
	}

	pub fn target(&self) -> &str {
		&self.target
	}

	pub fn name(&self) -> &str {
		&self.id
	}
}
