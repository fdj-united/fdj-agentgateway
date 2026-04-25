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

/// Per-backend rule that mutates a string field of a tool call's arguments
/// just before the request is forwarded upstream. Used for things like
/// appending a "sent via $TAG" footer to outbound message bodies.
///
/// The `tools` list is exact-match on the SHORT tool name (after multiplexing
/// resolution). `path` is a dot-separated JSON path inside `arguments`. The
/// path must resolve to a string; if it doesn't (missing, non-string, or any
/// intermediate non-object), the rule is skipped silently — we never inject
/// fields the upstream's tool schema doesn't expect.
#[apply(schema!)]
pub struct ArgRewriteRule {
	/// Tool names this rule applies to (short name after multiplexing).
	pub tools: Vec<String>,
	/// Dot-separated path inside the call's `arguments` map.
	pub path: String,
	/// How to combine `value` with the existing string at `path`. Defaults to `append`.
	#[serde(default)]
	pub op: RewriteOp,
	/// The text used by the operation. For `wrap`, may contain `{original}`
	/// which is substituted with the current value before assignment.
	pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum RewriteOp {
	Append,
	Prepend,
	Replace,
	Wrap,
}

impl Default for RewriteOp {
	fn default() -> Self {
		Self::Append
	}
}

/// Configuration for argument rewrites applied per backend.
#[apply(schema!)]
pub struct McpArgRewrite {
	pub rules: Vec<ArgRewriteRule>,
}

impl McpArgRewrite {
	pub fn into_inner(self) -> Vec<ArgRewriteRule> {
		self.rules
	}
}

/// Runtime view of merged argument-rewrite rules from one or more
/// [`McpArgRewrite`] entries attached to a backend.
#[derive(Clone, Debug, Default)]
pub struct McpArgRewriteSet {
	rules: Vec<ArgRewriteRule>,
}

impl McpArgRewriteSet {
	pub fn new(rules: Vec<ArgRewriteRule>) -> Self {
		Self { rules }
	}

	/// Apply every matching rule to `args` in-order.
	/// `tool_name` is the SHORT name (post-multiplexing).
	/// `args` is mutated in place; on a no-op (path not found / wrong type)
	/// the call is left untouched and a debug line is emitted.
	pub fn apply(
		&self,
		tool_name: &str,
		args: &mut Option<serde_json::Map<String, serde_json::Value>>,
	) {
		if self.rules.is_empty() {
			return;
		}
		let Some(map) = args.as_mut() else {
			return;
		};
		for rule in &self.rules {
			if !rule.tools.iter().any(|t| t == tool_name) {
				continue;
			}
			let Some(target) = walk_to_string_mut(map, &rule.path) else {
				tracing::debug!(
					"mcpArgRewrite: skipping rule for tool {} — path '{}' not found or not a string",
					tool_name,
					rule.path
				);
				continue;
			};
			match rule.op {
				RewriteOp::Append => target.push_str(&rule.value),
				RewriteOp::Prepend => *target = format!("{}{}", rule.value, target),
				RewriteOp::Replace => *target = rule.value.clone(),
				RewriteOp::Wrap => {
					let original = std::mem::take(target);
					*target = rule.value.replace("{original}", &original);
				},
			}
		}
	}
}

/// Resolve a dot-separated path to a mutable `&mut String` inside a JSON map.
/// Returns `None` if any segment doesn't exist, an intermediate value isn't
/// an object, or the leaf isn't a string.
fn walk_to_string_mut<'a>(
	args: &'a mut serde_json::Map<String, serde_json::Value>,
	path: &str,
) -> Option<&'a mut String> {
	let mut parts = path.split('.');
	let first = parts.next()?;
	let mut current: &mut serde_json::Value = args.get_mut(first)?;
	for part in parts {
		let map = match current {
			serde_json::Value::Object(m) => m,
			_ => return None,
		};
		current = map.get_mut(part)?;
	}
	match current {
		serde_json::Value::String(s) => Some(s),
		_ => None,
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
