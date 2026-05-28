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
	/// which is substituted with the current value before assignment. Ignored
	/// (and may be omitted) for `remove`.
	#[serde(default)]
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
	/// Delete a top-level key from the call's `arguments` map. Used to strip
	/// upstream toggles the agent should not be able to flip — e.g. the
	/// `excludeResponse` flag exposed by ms365-mcp that, when set, makes the
	/// upstream drop the response body (and with it the new object id the
	/// gateway needs for audit). `value` is ignored; `path` must be a
	/// top-level key (no `.` segments).
	Remove,
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
			// `Remove` bypasses walk_to_string_mut because the target can be ANY
			// type (boolean, object, array, …) — we delete the entry rather than
			// modify a string. Only top-level keys are supported (no dots);
			// nested paths are skipped with a debug line to keep behaviour
			// explicit.
			if matches!(rule.op, RewriteOp::Remove) {
				if rule.path.contains('.') {
					tracing::debug!(
						"mcpArgRewrite: 'remove' supports only top-level paths, skipping '{}' for tool {}",
						rule.path,
						tool_name
					);
					continue;
				}
				map.remove(&rule.path);
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
				// Handled above before walk_to_string_mut.
				RewriteOp::Remove => unreachable!(),
			}
		}
	}
}

/// One field to inject into a tool's input schema. The LLM populates this
/// from conversation context; the gateway shows the value in the confirmation
/// modal and strips it before forwarding the call upstream.
///
/// v1: only `string`-typed fields are supported.
#[apply(schema!)]
pub struct EnrichmentField {
	/// Property name added to `Tool.input_schema.properties`.
	pub name: String,
	/// JSON-schema type. v1 only supports "string".
	#[serde(rename = "type", default = "default_enrichment_type")]
	pub field_type: String,
	/// If true, name is added to `input_schema.required`. Defaults to `true`.
	#[serde(default = "default_true")]
	pub required: bool,
	/// Description text written verbatim into the JSON schema. This is the
	/// only signal the LLM gets about what to populate.
	pub description: String,
}

fn default_enrichment_type() -> String {
	"string".to_string()
}

fn default_true() -> bool {
	true
}

/// One enrichment rule, applied to every tool whose short name appears in
/// `tools`. Multiple rules whose `tools` lists overlap on the same tool all
/// apply (their `inject` lists are unioned). Field-name conflicts across
/// rules — or against an existing schema property — are caught at start time.
#[apply(schema!)]
pub struct EnrichmentRule {
	/// Tool short names this rule applies to (post-multiplexing).
	pub tools: Vec<String>,
	/// Synthetic fields injected into matching tools' input schemas.
	pub inject: Vec<EnrichmentField>,
}

/// Configuration for tool-schema enrichment, attached to a backend.
#[apply(schema!)]
pub struct McpToolEnrichment {
	pub rules: Vec<EnrichmentRule>,
}

impl McpToolEnrichment {
	pub fn into_inner(self) -> Vec<EnrichmentRule> {
		self.rules
	}
}

/// Runtime view of merged enrichment rules from one or more
/// [`McpToolEnrichment`] entries attached to a backend.
#[derive(Clone, Debug, Default)]
pub struct McpToolEnrichmentSet {
	rules: Vec<EnrichmentRule>,
}

impl McpToolEnrichmentSet {
	pub fn new(rules: Vec<EnrichmentRule>) -> Self {
		Self { rules }
	}

	pub fn is_empty(&self) -> bool {
		self.rules.is_empty()
	}

	/// Inject every matching rule's fields into `schema` (a JSON-schema object,
	/// the body of `Tool.input_schema`). `tool_name` is the SHORT tool name
	/// (post-multiplexing). On conflict — between an injected field and an
	/// existing schema property, or between two rules' injected fields on the
	/// same tool — returns Err describing the conflict.
	pub fn apply_to_schema(
		&self,
		tool_name: &str,
		schema: &mut serde_json::Map<String, serde_json::Value>,
	) -> anyhow::Result<()> {
		if self.rules.is_empty() {
			return Ok(());
		}
		// Collect every field that matches this tool, across all rules.
		let mut to_inject: Vec<&EnrichmentField> = Vec::new();
		for rule in &self.rules {
			if rule.tools.iter().any(|t| t == tool_name) {
				to_inject.extend(rule.inject.iter());
			}
		}
		if to_inject.is_empty() {
			return Ok(());
		}

		// Detect cross-rule conflicts on field name.
		let mut seen_names: std::collections::HashSet<&str> = std::collections::HashSet::new();
		for f in &to_inject {
			if !seen_names.insert(f.name.as_str()) {
				return Err(anyhow::anyhow!(
					"mcpToolEnrichment: tool '{}' has multiple rules injecting field '{}'; rename or merge the rules",
					tool_name,
					f.name
				));
			}
		}

		// Ensure `properties` exists; for an upstream that returned no
		// properties at all we still want to add ours. We DO NOT create
		// `required` unless we actually need it.
		let properties = schema
			.entry("properties".to_string())
			.or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
		let serde_json::Value::Object(props_map) = properties else {
			return Err(anyhow::anyhow!(
				"mcpToolEnrichment: tool '{}' has non-object `properties` in its schema",
				tool_name
			));
		};

		// Detect conflicts with existing properties.
		for f in &to_inject {
			if props_map.contains_key(&f.name) {
				return Err(anyhow::anyhow!(
					"mcpToolEnrichment: tool '{}' already has a property named '{}' — refusing to inject",
					tool_name,
					f.name
				));
			}
		}

		// Inject.
		for f in &to_inject {
			let mut field_schema = serde_json::Map::new();
			field_schema.insert("type".to_string(), serde_json::Value::String(f.field_type.clone()));
			field_schema.insert(
				"description".to_string(),
				serde_json::Value::String(f.description.clone()),
			);
			props_map.insert(f.name.clone(), serde_json::Value::Object(field_schema));
		}

		// Add to `required` for those marked required.
		let required_to_add: Vec<String> = to_inject
			.iter()
			.filter(|f| f.required)
			.map(|f| f.name.clone())
			.collect();
		if !required_to_add.is_empty() {
			let required = schema
				.entry("required".to_string())
				.or_insert_with(|| serde_json::Value::Array(Vec::new()));
			let serde_json::Value::Array(req_arr) = required else {
				return Err(anyhow::anyhow!(
					"mcpToolEnrichment: tool '{}' has non-array `required` in its schema",
					tool_name
				));
			};
			for name in required_to_add {
				req_arr.push(serde_json::Value::String(name));
			}
		}

		Ok(())
	}

	/// Detect cross-rule field-name collisions per tool, statically. This
	/// catches the most common operator misconfig (two rules injecting the
	/// same field name on the same tool) at config-construction time —
	/// before the gateway accepts traffic. The complementary dynamic case
	/// (a synthetic field colliding with an upstream tool's existing
	/// property) is detected at runtime by `apply_to_schema`.
	pub fn validate(&self) -> anyhow::Result<()> {
		use std::collections::{HashMap, HashSet};
		let mut by_tool: HashMap<&str, HashSet<&str>> = HashMap::new();
		for rule in &self.rules {
			for tool in &rule.tools {
				let seen = by_tool.entry(tool.as_str()).or_default();
				for field in &rule.inject {
					if !seen.insert(field.name.as_str()) {
						return Err(anyhow::anyhow!(
							"mcpToolEnrichment: tool '{}' has multiple rules injecting field '{}'; rename or merge the rules",
							tool,
							field.name
						));
					}
				}
			}
		}
		Ok(())
	}

	/// Remove every synthetic field declared in matching rules from `args`.
	/// `tool_name` is the SHORT tool name. Missing fields are no-ops; calling
	/// twice is identical to calling once.
	pub fn strip(
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
			for field in &rule.inject {
				map.remove(&field.name);
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
mod enrichment_tests {
	use super::*;
	use serde_json::{json, Map, Value};
	use serde_json::Map as JsonMap;

	#[test]
	fn enrichment_serde_roundtrip() {
		let yaml = r#"
rules:
  - tools: [send-chat-message]
    inject:
      - name: recipientDisplayName
        type: string
        description: "Human-readable recipient name."
"#;
		let parsed: McpToolEnrichment = serde_yaml::from_str(yaml).unwrap();
		assert_eq!(parsed.rules.len(), 1);
		assert_eq!(parsed.rules[0].tools, vec!["send-chat-message".to_string()]);
		assert_eq!(parsed.rules[0].inject.len(), 1);
		assert_eq!(parsed.rules[0].inject[0].name, "recipientDisplayName");
		// Default: required is true.
		assert!(parsed.rules[0].inject[0].required);
		assert_eq!(parsed.into_inner().len(), 1);
	}

	#[test]
	fn enrichment_required_explicit_false() {
		let yaml = r#"
rules:
  - tools: [t]
    inject:
      - name: f
        type: string
        required: false
        description: "x"
"#;
		let parsed: McpToolEnrichment = serde_yaml::from_str(yaml).unwrap();
		assert!(!parsed.rules[0].inject[0].required);
	}

	#[test]
	fn enrichment_set_default_is_empty() {
		let set = McpToolEnrichmentSet::default();
		assert!(set.is_empty());
	}

	fn schema_with(properties: Vec<(&str, Value)>) -> Map<String, Value> {
		let mut props = Map::new();
		for (k, v) in properties {
			props.insert(k.to_string(), v);
		}
		let mut schema = Map::new();
		schema.insert("type".to_string(), json!("object"));
		schema.insert("properties".to_string(), Value::Object(props));
		schema
	}

	fn one_rule(tool: &str, fields: Vec<(&str, bool, &str)>) -> McpToolEnrichmentSet {
		McpToolEnrichmentSet::new(vec![EnrichmentRule {
			tools: vec![tool.to_string()],
			inject: fields
				.into_iter()
				.map(|(name, required, desc)| EnrichmentField {
					name: name.to_string(),
					field_type: "string".to_string(),
					required,
					description: desc.to_string(),
				})
				.collect(),
		}])
	}

	#[test]
	fn apply_injects_property_for_matching_tool() {
		let set = one_rule("send-chat-message", vec![("recipientDisplayName", true, "name")]);
		let mut schema = schema_with(vec![("chatId", json!({"type": "string"}))]);
		set.apply_to_schema("send-chat-message", &mut schema).unwrap();

		let props = schema["properties"].as_object().unwrap();
		assert!(props.contains_key("recipientDisplayName"));
		let injected = &props["recipientDisplayName"];
		assert_eq!(injected["type"], json!("string"));
		assert_eq!(injected["description"], json!("name"));

		let required = schema["required"].as_array().unwrap();
		assert!(required.contains(&json!("recipientDisplayName")));
	}

	#[test]
	fn apply_skips_non_matching_tool() {
		let set = one_rule("send-chat-message", vec![("x", true, "x")]);
		let mut schema = schema_with(vec![("a", json!({"type": "string"}))]);
		set.apply_to_schema("some-other-tool", &mut schema).unwrap();

		let props = schema["properties"].as_object().unwrap();
		assert!(!props.contains_key("x"));
		assert!(schema.get("required").is_none());
	}

	#[test]
	fn apply_required_false_does_not_add_to_required() {
		let set = one_rule("t", vec![("f", false, "x")]);
		let mut schema = schema_with(vec![]);
		set.apply_to_schema("t", &mut schema).unwrap();

		let props = schema["properties"].as_object().unwrap();
		assert!(props.contains_key("f"));
		// `required` array either absent or does not contain "f".
		match schema.get("required") {
			None => {}
			Some(Value::Array(a)) => assert!(!a.contains(&json!("f"))),
			other => panic!("unexpected `required`: {other:?}"),
		}
	}

	#[test]
	fn apply_rejects_conflict_with_existing_property() {
		let set = one_rule("t", vec![("chatId", true, "x")]);
		let mut schema = schema_with(vec![("chatId", json!({"type": "string"}))]);
		let err = set.apply_to_schema("t", &mut schema).unwrap_err();
		assert!(err.to_string().contains("chatId"));
	}

	#[test]
	fn apply_rejects_conflict_across_rules() {
		let set = McpToolEnrichmentSet::new(vec![
			EnrichmentRule {
				tools: vec!["t".to_string()],
				inject: vec![EnrichmentField {
					name: "f".to_string(),
					field_type: "string".to_string(),
					required: true,
					description: "first".to_string(),
				}],
			},
			EnrichmentRule {
				tools: vec!["t".to_string()],
				inject: vec![EnrichmentField {
					name: "f".to_string(),
					field_type: "string".to_string(),
					required: true,
					description: "second".to_string(),
				}],
			},
		]);
		let mut schema = schema_with(vec![]);
		let err = set.apply_to_schema("t", &mut schema).unwrap_err();
		assert!(err.to_string().contains('f'));
	}

	#[test]
	fn validate_accepts_clean_config() {
		let set = McpToolEnrichmentSet::new(vec![
			EnrichmentRule {
				tools: vec!["a".to_string(), "b".to_string()],
				inject: vec![EnrichmentField {
					name: "f1".to_string(),
					field_type: "string".to_string(),
					required: true,
					description: "x".to_string(),
				}],
			},
			EnrichmentRule {
				tools: vec!["a".to_string()],
				inject: vec![EnrichmentField {
					name: "f2".to_string(),
					field_type: "string".to_string(),
					required: true,
					description: "y".to_string(),
				}],
			},
		]);
		set.validate().unwrap();
	}

	#[test]
	fn validate_rejects_cross_rule_duplicate_field_per_tool() {
		let set = McpToolEnrichmentSet::new(vec![
			EnrichmentRule {
				tools: vec!["a".to_string()],
				inject: vec![EnrichmentField {
					name: "dup".to_string(),
					field_type: "string".to_string(),
					required: true,
					description: "first".to_string(),
				}],
			},
			EnrichmentRule {
				tools: vec!["a".to_string(), "b".to_string()],
				inject: vec![EnrichmentField {
					name: "dup".to_string(),
					field_type: "string".to_string(),
					required: true,
					description: "second".to_string(),
				}],
			},
		]);
		let err = set.validate().unwrap_err();
		let msg = err.to_string();
		assert!(msg.contains("'a'"), "expected tool name 'a' in: {msg}");
		assert!(msg.contains("'dup'"), "expected field name 'dup' in: {msg}");
	}

	#[test]
	fn validate_rejects_same_rule_duplicate_field() {
		let set = McpToolEnrichmentSet::new(vec![EnrichmentRule {
			tools: vec!["a".to_string()],
			inject: vec![
				EnrichmentField {
					name: "dup".to_string(),
					field_type: "string".to_string(),
					required: true,
					description: "first".to_string(),
				},
				EnrichmentField {
					name: "dup".to_string(),
					field_type: "string".to_string(),
					required: true,
					description: "second".to_string(),
				},
			],
		}]);
		let err = set.validate().unwrap_err();
		assert!(err.to_string().contains("'dup'"));
	}

	#[test]
	fn validate_allows_same_field_name_on_different_tools() {
		// Two rules each declaring the same field name, but for DIFFERENT
		// tools — that's fine, no conflict per tool.
		let set = McpToolEnrichmentSet::new(vec![
			EnrichmentRule {
				tools: vec!["a".to_string()],
				inject: vec![EnrichmentField {
					name: "f".to_string(),
					field_type: "string".to_string(),
					required: true,
					description: "x".to_string(),
				}],
			},
			EnrichmentRule {
				tools: vec!["b".to_string()],
				inject: vec![EnrichmentField {
					name: "f".to_string(),
					field_type: "string".to_string(),
					required: true,
					description: "y".to_string(),
				}],
			},
		]);
		set.validate().unwrap();
	}

	fn args_with(pairs: Vec<(&str, Value)>) -> Option<JsonMap<String, Value>> {
		let mut m = JsonMap::new();
		for (k, v) in pairs {
			m.insert(k.to_string(), v);
		}
		Some(m)
	}

	#[test]
	fn strip_removes_matching_synthetic_field() {
		let set = one_rule("t", vec![("display", true, "x")]);
		let mut args = args_with(vec![
			("chatId", json!("19:abc")),
			("display", json!("Alice")),
		]);
		set.strip("t", &mut args);

		let m = args.unwrap();
		assert!(!m.contains_key("display"));
		assert!(m.contains_key("chatId"));
	}

	#[test]
	fn strip_is_noop_for_non_matching_tool() {
		let set = one_rule("t", vec![("display", true, "x")]);
		let mut args = args_with(vec![("display", json!("Alice"))]);
		set.strip("other", &mut args);
		assert!(args.unwrap().contains_key("display"));
	}

	#[test]
	fn strip_is_noop_when_field_absent() {
		let set = one_rule("t", vec![("display", true, "x")]);
		let mut args = args_with(vec![("chatId", json!("19:abc"))]);
		set.strip("t", &mut args);
		let m = args.unwrap();
		assert_eq!(m.len(), 1);
		assert!(m.contains_key("chatId"));
	}

	#[test]
	fn strip_is_idempotent() {
		let set = one_rule("t", vec![("display", true, "x")]);
		let mut args = args_with(vec![("display", json!("Alice"))]);
		set.strip("t", &mut args);
		set.strip("t", &mut args);
		assert!(args.unwrap().is_empty());
	}

	#[test]
	fn strip_then_hash_is_stable_across_synthetic_value_changes() {
		// This is the load-bearing invariant: Phase-2 confirmation match
		// must survive the LLM producing a different synthetic value than
		// it did in Phase 1. (See spec §6.)
		use crate::mcp::session::hash_args;
		let set = one_rule("t", vec![("display", true, "x")]);

		let mut a1 = args_with(vec![
			("chatId", json!("19:abc")),
			("display", json!("Alice")),
		]);
		set.strip("t", &mut a1);
		let h1 = hash_args(a1.as_ref());

		let mut a2 = args_with(vec![
			("chatId", json!("19:abc")),
			("display", json!("Alice S.")),
		]);
		set.strip("t", &mut a2);
		let h2 = hash_args(a2.as_ref());

		assert_eq!(h1, h2);
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
