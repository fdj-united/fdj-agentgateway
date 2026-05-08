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
	/// Optional structured presentation rules — one per matching tool. When a
	/// tool call triggers confirmation, the gateway attaches a `presentation`
	/// block to the envelope using the first rule whose `tools` list matches.
	/// The client uses this to render a friendly modal instead of the raw
	/// `preview` text.
	#[serde(default)]
	pub presentations: Vec<PresentationRule>,
}

impl McpConfirmation {
	pub fn into_parts(self) -> (RuleSet, Option<u64>, Vec<PresentationRule>) {
		(self.rules, self.ttl_seconds, self.presentations)
	}
}

/// Suggested format for a single presentation field. Used as a hint by the
/// client renderer; unrecognized values fall back to `text`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum PresentationFormat {
	/// Free-text — the dominant user-facing string (e.g. message body).
	Text,
	/// Inline code / identifier (chat IDs, URLs, hashes).
	Code,
	/// Pretty-printed JSON (objects, arrays).
	Json,
	/// Markdown content (will be rendered as such if the client supports it).
	Markdown,
}

impl Default for PresentationFormat {
	fn default() -> Self {
		Self::Text
	}
}

/// Whether a field is part of the at-a-glance summary or hidden behind a
/// "show details" affordance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum PresentationImportance {
	/// Always visible.
	Primary,
	/// Hidden under a "show details" toggle by default.
	Detail,
}

impl Default for PresentationImportance {
	fn default() -> Self {
		Self::Primary
	}
}

/// A single labeled field projected out of the tool's call arguments. The
/// client will render `label` and the resolved value at `path`.
#[apply(schema!)]
pub struct PresentationFieldSpec {
	/// Human-readable label shown to the user (e.g. "Message", "To").
	pub label: String,
	/// Dot-separated path inside the call's `arguments` map. Same syntax as
	/// `McpArgRewrite.path`. If the path resolves to a missing or null value
	/// the field is silently dropped from the rendered presentation.
	pub path: String,
	#[serde(default)]
	pub format: PresentationFormat,
	#[serde(default)]
	pub importance: PresentationImportance,
}

/// One presentation rule, applied when an incoming tool call's short name
/// matches `tools`. The first matching rule wins (no merging across rules).
#[apply(schema!)]
pub struct PresentationRule {
	/// Tool short names this rule applies to (post-multiplexing).
	pub tools: Vec<String>,
	/// One-line title shown in the modal header. Optional — falls back to the
	/// raw tool name on the client side.
	#[serde(default)]
	pub title: Option<String>,
	/// Optional one-sentence summary placed under the title.
	#[serde(default)]
	pub summary: Option<String>,
	/// Ordered list of fields to render.
	pub fields: Vec<PresentationFieldSpec>,
}

/// Runtime collection of confirmation rules, built from one or more
/// [`McpConfirmation`] policy entries.
#[derive(Clone, Debug)]
pub struct McpConfirmationSet {
	rules: RuleSets,
	/// How long a pending approval remains valid before expiring.
	pub ttl: Duration,
	/// Per-tool presentation rules merged across config entries; first match
	/// wins when building the envelope.
	presentations: Vec<PresentationRule>,
}

impl McpConfirmationSet {
	pub fn new(rules: RuleSets, ttl: Duration, presentations: Vec<PresentationRule>) -> Self {
		Self {
			rules,
			ttl,
			presentations,
		}
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

	/// Build a structured presentation block for this tool call, suitable for
	/// JSON-serialising into the confirmation envelope. Returns `None` when
	/// no rule matches `tool_name` — callers should fall back to the raw
	/// `preview` string in that case.
	pub fn build_presentation(
		&self,
		tool_name: &str,
		args: Option<&serde_json::Map<String, serde_json::Value>>,
	) -> Option<serde_json::Value> {
		let rule = self
			.presentations
			.iter()
			.find(|r| r.tools.iter().any(|t| t == tool_name))?;

		let mut fields_out: Vec<serde_json::Value> = Vec::new();
		if let Some(map) = args {
			for spec in &rule.fields {
				let Some(value) = walk_to_value(map, &spec.path) else {
					continue;
				};
				fields_out.push(serde_json::json!({
					"label": spec.label,
					"value": value,
					"format": match spec.format {
						PresentationFormat::Text => "text",
						PresentationFormat::Code => "code",
						PresentationFormat::Json => "json",
						PresentationFormat::Markdown => "markdown",
					},
					"importance": match spec.importance {
						PresentationImportance::Primary => "primary",
						PresentationImportance::Detail => "detail",
					},
				}));
			}
		}

		// Drop the presentation entirely if every field path missed — the raw
		// preview is a strictly better fallback than an empty card.
		if fields_out.is_empty() {
			return None;
		}

		let mut obj = serde_json::Map::new();
		if let Some(t) = &rule.title {
			obj.insert("title".to_string(), serde_json::Value::String(t.clone()));
		}
		if let Some(s) = &rule.summary {
			obj.insert("summary".to_string(), serde_json::Value::String(s.clone()));
		}
		obj.insert("fields".to_string(), serde_json::Value::Array(fields_out));
		Some(serde_json::Value::Object(obj))
	}
}

/// Resolve a dot-separated path to a borrowed `serde_json::Value` for read-only
/// inspection. Mirrors `walk_to_string_mut` but returns the raw value (string
/// or otherwise) so the presenter can preserve type information.
fn walk_to_value<'a>(
	args: &'a serde_json::Map<String, serde_json::Value>,
	path: &str,
) -> Option<&'a serde_json::Value> {
	let mut parts = path.split('.');
	let first = parts.next()?;
	let mut current: &serde_json::Value = args.get(first)?;
	for part in parts {
		let map = match current {
			serde_json::Value::Object(m) => m,
			_ => return None,
		};
		current = map.get(part)?;
	}
	Some(current)
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
			presentations: Vec::new(),
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

#[cfg(test)]
mod presentation_tests {
	use super::*;

	fn args(map: serde_json::Value) -> Option<serde_json::Map<String, serde_json::Value>> {
		match map {
			serde_json::Value::Object(m) => Some(m),
			_ => None,
		}
	}

	fn rule_set() -> McpConfirmationSet {
		McpConfirmationSet::new(
			RuleSets::from(Vec::new()),
			Duration::from_secs(120),
			vec![PresentationRule {
				tools: vec!["send-chat-message".to_string()],
				title: Some("Send Teams message".to_string()),
				summary: Some("Send a chat message to a Teams conversation".to_string()),
				fields: vec![
					PresentationFieldSpec {
						label: "To".to_string(),
						path: "chatId".to_string(),
						format: PresentationFormat::Code,
						importance: PresentationImportance::Primary,
					},
					PresentationFieldSpec {
						label: "Message".to_string(),
						path: "body.content".to_string(),
						format: PresentationFormat::Text,
						importance: PresentationImportance::Primary,
					},
					PresentationFieldSpec {
						label: "Format".to_string(),
						path: "body.contentType".to_string(),
						format: PresentationFormat::Code,
						importance: PresentationImportance::Detail,
					},
				],
			}],
		)
	}

	#[test]
	fn returns_none_when_no_rule_matches_tool_name() {
		let set = rule_set();
		let a = args(serde_json::json!({"chatId": "19:abc"}));
		let result = set.build_presentation("not-a-known-tool", a.as_ref());
		assert!(result.is_none());
	}

	#[test]
	fn projects_dot_paths_into_field_values() {
		let set = rule_set();
		let a = args(serde_json::json!({
			"chatId": "19:abc",
			"body": { "content": "hi", "contentType": "text" },
		}));
		let result = set
			.build_presentation("send-chat-message", a.as_ref())
			.expect("expected presentation");
		let fields = result.get("fields").and_then(|v| v.as_array()).unwrap();
		assert_eq!(fields.len(), 3);
		assert_eq!(fields[0].get("label").unwrap(), "To");
		assert_eq!(fields[0].get("value").unwrap(), "19:abc");
		assert_eq!(fields[0].get("format").unwrap(), "code");
		assert_eq!(fields[0].get("importance").unwrap(), "primary");
		assert_eq!(fields[1].get("label").unwrap(), "Message");
		assert_eq!(fields[1].get("value").unwrap(), "hi");
		assert_eq!(fields[2].get("importance").unwrap(), "detail");
		assert_eq!(result.get("title").unwrap(), "Send Teams message");
	}

	#[test]
	fn drops_missing_paths_silently() {
		let set = rule_set();
		// No `body` map at all → only chatId resolves; the two body.* fields drop.
		let a = args(serde_json::json!({"chatId": "19:abc"}));
		let result = set
			.build_presentation("send-chat-message", a.as_ref())
			.expect("expected presentation");
		let fields = result.get("fields").and_then(|v| v.as_array()).unwrap();
		assert_eq!(fields.len(), 1);
		assert_eq!(fields[0].get("label").unwrap(), "To");
	}

	#[test]
	fn returns_none_when_every_path_misses() {
		let set = rule_set();
		let a = args(serde_json::json!({"unrelated": "value"}));
		let result = set.build_presentation("send-chat-message", a.as_ref());
		assert!(result.is_none());
	}

	#[test]
	fn preserves_non_string_value_types() {
		let mut set = rule_set();
		set.presentations[0].fields = vec![PresentationFieldSpec {
			label: "Payload".to_string(),
			path: "body".to_string(),
			format: PresentationFormat::Json,
			importance: PresentationImportance::Primary,
		}];
		let a = args(serde_json::json!({"body": {"content": "hi"}}));
		let result = set
			.build_presentation("send-chat-message", a.as_ref())
			.expect("expected presentation");
		let fields = result.get("fields").and_then(|v| v.as_array()).unwrap();
		assert!(fields[0].get("value").unwrap().is_object());
	}
}
