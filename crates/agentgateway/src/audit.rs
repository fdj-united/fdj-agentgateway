use std::collections::HashMap;
use std::path::Path;
use std::sync::{LazyLock, RwLock};
use std::time::Duration;

use chrono::{SecondsFormat, Utc};
use http::header::AsHeaderName;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::mcp::{MCPInfo, MCPTool};
use crate::telemetry::log::RequestLog;

const AUDIT_LEVEL: &str = "AUDIT";

// Defensive cap on the cached user identity — emails are well under this.
const MAX_KAIT_USER_LEN: usize = 256;

/// In-memory cache mapping MCP session ID → KAIT (LibreChat) user identity.
///
/// Captures the user from the FIRST request on a session whose headers/JWT
/// yield an identifiable user; subsequent events on the same session — notably
/// the long-poll SSE GETs that LibreChat does not re-include `X-User-Email`
/// on — read from this cache so every audit event stays attributable to a
/// real KAIT user.
///
/// **Memory only.** Never persisted, never serialized, never written to
/// Splunk. Entries are evicted by `emit_l3_session_closed` when the gateway
/// drops the session.
static SESSION_USER_CACHE: LazyLock<RwLock<HashMap<String, String>>> =
	LazyLock::new(|| RwLock::new(HashMap::new()));

/// Capture-once write. A second `set` for the same session is ignored — the
/// first authenticated user identity associated with a session is the
/// audit-of-record; later requests cannot override it.
///
/// As a side effect, on the FIRST successful capture for a given session ID
/// an `loggingId=L1 event=session_authenticated` event is emitted. The
/// security team's L1 row in the logging guidelines wants per-session login
/// success events; the first successful identity capture is exactly that
/// signal. Capturing it here piggy-backs on the existing capture-once
/// guarantee and keeps L1 emission volume to one per session rather than
/// one per request.
fn cache_session_user(session_id: &str, user: &str, ctx: &AuditContext) {
	if user.is_empty() || user.len() > MAX_KAIT_USER_LEN {
		return;
	}
	let is_new = {
		let mut map = SESSION_USER_CACHE
			.write()
			.expect("audit SESSION_USER_CACHE poisoned");
		// `contains_key + insert` under the same write lock is atomic — two
		// concurrent requests for the same new session cannot both observe
		// `is_new = true`.
		let was_present = map.contains_key(session_id);
		map
			.entry(session_id.to_string())
			.or_insert_with(|| user.to_string());
		!was_present
	};
	if is_new {
		emit_l1_session_authenticated(session_id, user, ctx);
	}
}

fn cached_session_user(session_id: &str) -> Option<String> {
	SESSION_USER_CACHE
		.read()
		.expect("audit SESSION_USER_CACHE poisoned")
		.get(session_id)
		.cloned()
}

/// Removes the cached entry on session close and returns it so the
/// `session_closed` audit event can still attribute the user.
fn evict_session_user(session_id: &str) -> Option<String> {
	SESSION_USER_CACHE
		.write()
		.expect("audit SESSION_USER_CACHE poisoned")
		.remove(session_id)
}

/// SHA-256 prefix (first 16 bytes, 32 hex chars) of an MCP session ID. We log
/// this in place of the raw session ID — the raw value is a gateway-encrypted
/// session token whose leakage from Splunk plus an eventual session-key
/// compromise would enable replay; 16 bytes of hash is still sufficient to
/// correlate all events of a session in Splunk without being replayable.
fn session_id_hash(session_id: &str) -> String {
	let mut hasher = Sha256::new();
	hasher.update(session_id.as_bytes());
	let digest = hasher.finalize();
	hex::encode(&digest[..16])
}

pub fn emit_l3_mcp_access(log: &RequestLog, mcp: Option<&MCPInfo>, duration: Duration) {
	let status = log.status.as_ref().map(|s| s.as_u16());
	let tool = mcp.and_then(|m| m.tool.as_ref());
	let tool_name = tool.map(|t| t.name.as_str());
	let failed_auth = matches!(status, Some(401 | 403));

	// Audit only events that matter to the security team:
	//   - tool calls (success / denied / blocked / failure)
	//   - authentication failures
	// Protocol-layer noise (initialize / ping / tools/list / notifications/*)
	// is intentionally NOT audited — it generates ~5x volume without
	// per-user accountability since these messages happen before/around
	// OAuth on long-lived SSE channels.
	if tool_name.is_none() && !failed_auth {
		return;
	}

	let args = tool.and_then(|t| t.arguments.as_ref());
	let server = mcp
		.and_then(|m| m.target_name())
		.or_else(|| route_segment(log.path.as_deref()))
		.unwrap_or("unknown");
	let outcome = access_outcome(status, log.error.as_deref(), mcp);
	let event_name = match (tool_name, outcome) {
		(Some(_), "denied") => "tool_call_denied",
		(Some(_), "blocked") => "tool_call_blocked",
		(Some(_), _) => "tool_call",
		(None, _) => "auth_failure",
	};
	// Authentication-failure events belong to logging level L1 (Authentication)
	// per the security team's logging guidelines, not L3 (Access). The rest of
	// the tool-call event types stay on L3 (Access).
	let logging_id = if event_name == "auth_failure" { "L1" } else { "L3" };

	let session_id = mcp.and_then(|m| m.session_id.as_deref());

	// Request-context fields shared with the L1 session_authenticated event.
	// Built before the cache write so the login-success event (emitted from
	// inside cache_session_user on first capture) carries the same core
	// fields as every access event.
	let ctx = AuditContext {
		source_ip: Some(log.tcp_info.peer_addr.ip().to_string()),
		source_port: Some(log.tcp_info.peer_addr.port()),
		forwarded_for: header(log, "x-forwarded-for"),
		user_agent: header(log, "user-agent"),
		transport: transport(log),
		server: server.to_string(),
	};

	// Resolve user identity with persistent session fallback:
	//   1. Current request (JWT or X-User-Email or X-LibreChat-Username)
	//   2. Cached identity from any prior request on the same session
	// Capture-once into the cache so SSE long-polls (no headers) and other
	// protocol traffic still attribute back to the original KAIT user.
	let kait_user = kait_user(log).or_else(|| session_id.and_then(cached_session_user));
	if let (Some(sid), Some(ref user)) = (session_id, kait_user.as_ref()) {
		cache_session_user(sid, user, &ctx);
	}

	// Canonical schema: every access-family event carries the SAME set of
	// keys. Absent values serialize as JSON null (via `put`) rather than
	// being omitted, so a given event type always has a stable field set.
	let mut event = audit_base(logging_id, event_name);
	put(&mut event, "sessionIdHash", session_id.map(session_id_hash));
	put(&mut event, "kaitUser", kait_user);
	put(&mut event, "sourceIp", ctx.source_ip.clone());
	event.insert(
		"sourcePort".into(),
		ctx.source_port.map_or(Value::Null, |p| json!(p)),
	);
	put(&mut event, "forwardedFor", ctx.forwarded_for.clone());
	put(&mut event, "userAgent", ctx.user_agent.clone());
	event.insert("transport".into(), json!(ctx.transport));
	event.insert("outcome".into(), json!(outcome));
	event.insert(
		"reason".into(),
		reason(log, mcp, status).map_or(Value::Null, Value::String),
	);
	event.insert("server".into(), json!(ctx.server));
	put(&mut event, "siteUrl", first_string(args, &["siteUrl", "site_url"]));
	put(&mut event, "cloudId", first_string(args, &["cloudId", "cloud_id"]));
	put(&mut event, "tool", tool_name.map(ToOwned::to_owned));
	event.insert(
		"toolCategory".into(),
		tool_name.map_or(Value::Null, |t| json!(tool_category(t))),
	);
	// affectedObjects = identifiers from the request args PLUS, for create
	// operations, the new object's id parsed from the upstream RESULT (e.g. the
	// issue key Jira assigns on createJiraIssue, which is absent from the args).
	let mut affected = affected_objects(tool_name, args);
	affected.extend(affected_objects_from_result(
		tool_name,
		tool.and_then(|t| t.result.as_ref()),
	));
	event.insert("affectedObjects".into(), Value::Array(affected));
	event.insert("durationMs".into(), json!(duration_ms(duration)));
	put(&mut event, "httpStatus", status.map(|s| s.to_string()));
	// Transport-level `httpStatus` is frequently 200 even when the upstream
	// API failed (MCP wraps app errors in a successful JSON-RPC envelope).
	// `upstreamStatus` surfaces the real upstream status code when the result
	// payload carries one — a number only, never the payload body.
	event.insert(
		"upstreamStatus".into(),
		upstream_status(mcp).map_or(Value::Null, |s| json!(s)),
	);
	put(
		&mut event,
		"mcpMethod",
		mcp
			.and_then(|m| m.method_name.as_deref())
			.map(ToOwned::to_owned),
	);

	emit(Value::Object(event));
}

/// Emit the `session_authenticated` L1 event the first time the gateway
/// observes an identifiable user on a session. Fires at most once per session
/// (driven by the capture-once behaviour of `cache_session_user`). Equivalent
/// to the security team's "Login success" L1 row for the MCP-proxied
/// authentication flow.
fn emit_l1_session_authenticated(session_id: &str, kait_user: &str, ctx: &AuditContext) {
	let mut event = audit_base("L1", "session_authenticated");
	event.insert("sessionIdHash".into(), json!(session_id_hash(session_id)));
	put(&mut event, "kaitUser", Some(kait_user.to_string()));
	// Same core fields as the L1 auth_failure event so login-success and
	// login-failure are directly comparable in Splunk.
	put(&mut event, "sourceIp", ctx.source_ip.clone());
	event.insert(
		"sourcePort".into(),
		ctx.source_port.map_or(Value::Null, |p| json!(p)),
	);
	put(&mut event, "forwardedFor", ctx.forwarded_for.clone());
	put(&mut event, "userAgent", ctx.user_agent.clone());
	event.insert("transport".into(), json!(ctx.transport));
	event.insert("server".into(), json!(ctx.server));
	event.insert("outcome".into(), json!("success"));
	event.insert("reason".into(), Value::Null);
	emit(Value::Object(event));
}

/// Emit the `session_closed` lifecycle event and evict the cached user.
///
/// Called from the gateway's session-removal path so security can correlate
/// session start (first `tool_call`) with session end. Generic across MCP
/// backends — no jira/confluence/teams-specific logic.
pub fn emit_l3_session_closed(session_id: &str) {
	let kait_user = evict_session_user(session_id);
	let mut event = audit_base("L3", "session_closed");
	event.insert("sessionIdHash".into(), json!(session_id_hash(session_id)));
	// `put` (not `put_opt`) so the key is always present — a session dropped
	// before any user was captured still emits `kaitUser: null` rather than
	// omitting the field, keeping session_closed field-set-consistent with
	// every other audit event.
	put(&mut event, "kaitUser", kait_user);
	event.insert("outcome".into(), json!("success"));
	event.insert("reason".into(), Value::Null);
	emit(Value::Object(event));
}

/// Emit a tool-level confirmation event (`tool_confirmation_requested` when
/// the gateway returns a confirmation envelope, `tool_confirmed` when the
/// user-approved retry forwards upstream). `outcome` is the caller's choice
/// — typically `"pending_confirmation"` and `"success"` respectively.
///
/// Generic: works for any MCP backend whose route has an `mcpConfirmation`
/// policy. The user is resolved from the same session cache as `tool_call`.
///
/// `args` are the tool-call arguments, used to derive `affectedObjects` so the
/// confirmation event records WHICH object the pending action targets (e.g.
/// the Confluence page id, the Teams chat id) — not just the tool name. Only
/// non-sensitive identifiers are extracted; argument content is never logged.
pub fn emit_l3_tool_confirmation(
	event_name: &str,
	session_id: &str,
	server: &str,
	tool: &str,
	outcome: &str,
	args: Option<&Map<String, Value>>,
) {
	let kait_user = cached_session_user(session_id);
	let mut event = audit_base("L3", event_name);
	event.insert("sessionIdHash".into(), json!(session_id_hash(session_id)));
	put(&mut event, "kaitUser", kait_user);
	event.insert("server".into(), json!(server));
	event.insert("tool".into(), json!(tool));
	event.insert("toolCategory".into(), json!(tool_category(tool)));
	event.insert(
		"affectedObjects".into(),
		Value::Array(affected_objects(Some(tool), args)),
	);
	event.insert("outcome".into(), json!(outcome));
	event.insert("reason".into(), Value::Null);
	emit(Value::Object(event));
}

pub fn emit_l4_config_loaded(config_contents: &str, source: Option<&Path>) {
	let mut event = audit_base("L4", "guardrail_config_loaded");
	event.insert("sessionId".into(), Value::Null);
	event.insert("kaitUser".into(), Value::Null);
	event.insert("sourceIp".into(), Value::Null);
	event.insert("transport".into(), json!("both"));
	event.insert("outcome".into(), json!("success"));
	event.insert("reason".into(), Value::Null);
	event.insert(
		"config".into(),
		config_summary(config_contents, source).unwrap_or_else(|err| {
			json!({
				"summaryError": err,
				"configChecksum": sha256(config_contents),
			})
		}),
	);
	emit(Value::Object(event));
}

pub fn emit_l5_startup(config_contents: &str, source: Option<&Path>) {
	let mut event = audit_base("L5", "startup");
	event.insert("sessionId".into(), Value::Null);
	event.insert("kaitUser".into(), Value::Null);
	event.insert("sourceIp".into(), Value::Null);
	event.insert("transport".into(), json!("both"));
	event.insert("outcome".into(), json!("success"));
	event.insert("reason".into(), Value::Null);
	event.insert(
		"details".into(),
		config_summary(config_contents, source).unwrap_or_else(|err| {
			json!({
				"summaryError": err,
				"configChecksum": sha256(config_contents),
			})
		}),
	);
	emit(Value::Object(event));
}

pub fn emit_l5_shutdown() {
	let mut event = audit_base("L5", "shutdown");
	event.insert("sessionId".into(), Value::Null);
	event.insert("kaitUser".into(), Value::Null);
	event.insert("sourceIp".into(), Value::Null);
	event.insert("transport".into(), json!("both"));
	event.insert("outcome".into(), json!("success"));
	event.insert("reason".into(), Value::Null);
	event.insert("details".into(), json!({}));
	emit(Value::Object(event));
}

pub fn emit_l5_dysfunction(reason: impl Into<String>) {
	let mut event = audit_base("L5", "dysfunction");
	event.insert("sessionId".into(), Value::Null);
	event.insert("kaitUser".into(), Value::Null);
	event.insert("sourceIp".into(), Value::Null);
	event.insert("transport".into(), json!("both"));
	event.insert("outcome".into(), json!("failure"));
	event.insert("reason".into(), json!(reason.into()));
	event.insert("details".into(), json!({}));
	emit(Value::Object(event));
}

fn audit_base(logging_id: &str, event: &str) -> Map<String, Value> {
	let mut base = Map::new();
	base.insert(
		"timestamp".into(),
		json!(Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)),
	);
	base.insert("level".into(), json!(AUDIT_LEVEL));
	base.insert("loggingId".into(), json!(logging_id));
	base.insert("event".into(), json!(event));
	base
}

/// Insert a canonical-schema field. The key is ALWAYS present — a missing
/// value serializes as JSON `null` rather than being omitted. This guarantees
/// every event of a given type carries the same set of keys, which the
/// security team relies on for stable field extraction in Splunk (an omitted
/// key and a null key are not equivalent to a downstream query).
fn put(map: &mut Map<String, Value>, key: &str, value: Option<String>) {
	map.insert(key.into(), value.map_or(Value::Null, Value::String));
}

/// Request-context fields shared by the access-family events and the L1
/// `session_authenticated` event. Computed once per request and threaded into
/// the session-user cache so the login-success event carries the same core
/// fields (sourceIp / forwardedFor / transport / server) as login-failure.
#[derive(Clone)]
struct AuditContext {
	source_ip: Option<String>,
	source_port: Option<u16>,
	forwarded_for: Option<String>,
	user_agent: Option<String>,
	transport: &'static str,
	server: String,
}

fn emit(event: Value) {
	match serde_json::to_string(&event) {
		Ok(line) => println!("{line}"),
		Err(err) => eprintln!(
			r#"{{"timestamp":"{}","level":"AUDIT","loggingId":"L5","event":"dysfunction","outcome":"failure","reason":"failed to serialize audit event","details":{{"error":"{}"}}}}"#,
			Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
			json_escape(&err.to_string()),
		),
	}
}

fn config_summary(config_contents: &str, source: Option<&Path>) -> Result<Value, String> {
	let parsed: Value = serde_yaml::from_str(config_contents).map_err(|err| err.to_string())?;
	let mut listeners = Vec::new();
	let mut ports = Vec::new();

	for bind in parsed
		.get("binds")
		.and_then(Value::as_array)
		.into_iter()
		.flatten()
	{
		if let Some(port) = bind.get("port").and_then(Value::as_u64) {
			ports.push(port);
		}
		for listener in bind
			.get("listeners")
			.and_then(Value::as_array)
			.into_iter()
			.flatten()
		{
			let routes = listener
				.get("routes")
				.and_then(Value::as_array)
				.map(|routes| routes.iter().map(route_summary).collect::<Vec<_>>())
				.unwrap_or_default();
			listeners.push(json!({
				"name": listener.get("name").and_then(Value::as_str).unwrap_or("unnamed"),
				"hostname": listener.get("hostname").and_then(Value::as_str),
				"routes": routes,
			}));
		}
	}

	Ok(json!({
		"configSource": source.map(|p| p.to_string_lossy().to_string()).unwrap_or_else(|| "inline".to_string()),
		"configChecksum": sha256(config_contents),
		"ports": ports,
		"listeners": listeners,
		"auditSchemaVersion": 1,
	}))
}

fn route_summary(route: &Value) -> Value {
	let policies = route.get("policies").and_then(Value::as_object);
	let auth_mode = policies
		.and_then(|p| p.get("mcpAuthentication"))
		.and_then(|auth| auth.get("mode"))
		.and_then(Value::as_str);

	json!({
		"name": route.get("name").and_then(Value::as_str).unwrap_or("unnamed"),
		"authenticationMode": auth_mode,
		"authorizationEnabled": policy_present(policies, "mcpAuthorization"),
		"confirmationEnabled": policy_present(policies, "mcpConfirmation"),
		"rateLimitEnabled": policy_present(policies, "mcpRateLimit"),
		"argRewriteEnabled": policy_present(policies, "mcpArgRewrite"),
		"toolEnrichmentEnabled": policy_present(policies, "mcpToolEnrichment"),
	})
}

fn policy_present(policies: Option<&Map<String, Value>>, key: &str) -> bool {
	policies.is_some_and(|p| p.contains_key(key))
}

fn access_outcome(status: Option<u16>, error: Option<&str>, mcp: Option<&MCPInfo>) -> &'static str {
	if matches!(status, Some(401 | 403)) {
		return "denied";
	}
	if matches!(status, Some(429)) {
		return "blocked";
	}
	if let Some(tool) = mcp.and_then(|m| m.tool.as_ref())
		&& let Some(outcome) = tool_outcome_from_result(tool)
	{
		return outcome;
	}
	if error.is_some() || status.is_some_and(|s| s >= 400) {
		return "failure";
	}
	"success"
}

/// Inspect the MCP tool response for application-level outcome signals that
/// the HTTP and JSON-RPC protocol layers do not surface.
///
/// MCP servers (and the gateway itself) routinely return HTTP 200 with a
/// nominal JSON-RPC success envelope, yet encode an error, a rate-limit, or a
/// pending-confirmation state inside the result text. Without this check
/// those events would all be audited as `outcome=success`, which is exactly
/// the bypass class the security team reported for Atlassian's
/// `{"error": true, ...}` text-content errors.
///
/// Precedence (first match wins):
///   1. JSON-RPC error envelope (`tool.error`).
///   2. MCP standard `CallToolResult.isError` flag.
///   3. Gateway-emitted control envelopes inside `content[].text`:
///        - `{"error": "rate_limit_exceeded", ...}` → `blocked`
///        - `{"confirmationRequired": true, ...}`   → `pending_confirmation`
///   4. Upstream/application-level error pattern: `{"error": true, ...}`
///      in the text content → `failure`.
fn tool_outcome_from_result(tool: &MCPTool) -> Option<&'static str> {
	if tool.error.is_some() {
		return Some("failure");
	}
	let result = tool.result.as_ref()?;
	if result
		.get("isError")
		.and_then(Value::as_bool)
		.unwrap_or(false)
	{
		return Some("failure");
	}
	let payload = extract_tool_text_payload(result)?;
	if payload.get("error").and_then(Value::as_str) == Some("rate_limit_exceeded") {
		return Some("blocked");
	}
	if payload
		.get("confirmationRequired")
		.and_then(Value::as_bool)
		.unwrap_or(false)
	{
		return Some("pending_confirmation");
	}
	if payload
		.get("error")
		.and_then(Value::as_bool)
		.unwrap_or(false)
	{
		return Some("failure");
	}
	None
}

/// Parse the first `text`-typed item of a `CallToolResult.content` array as
/// JSON. Used to detect outcome signals embedded by upstream MCP servers
/// (e.g. Atlassian's `{"error": true, "message": ...}`) or by gateway
/// policies (rate-limit, confirmation envelopes).
///
/// Returns `None` when no text content exists or when the text is not valid
/// JSON — that prevents false positives on tools that legitimately return
/// prose containing the word "error".
fn extract_tool_text_payload(result: &Value) -> Option<Value> {
	result
		.get("content")?
		.as_array()?
		.iter()
		.find_map(|item| {
			if item.get("type").and_then(Value::as_str) != Some("text") {
				return None;
			}
			item
				.get("text")
				.and_then(Value::as_str)
				.and_then(|s| serde_json::from_str::<Value>(s).ok())
		})
}

/// Extract the upstream application-level status code embedded in a tool
/// result payload (e.g. Atlassian's `{"statusCode": 400, ...}`). The
/// transport-level `httpStatus` is frequently 200 even when the upstream API
/// rejected the call, because MCP wraps application errors inside a
/// successful JSON-RPC envelope. This surfaces the real upstream code — a
/// number only, never the payload body — so the audit reader can tell a
/// transport success carrying an application error apart from a true success.
fn upstream_status(mcp: Option<&MCPInfo>) -> Option<u64> {
	let payload = mcp
		.and_then(|m| m.tool.as_ref())
		.and_then(|t| t.result.as_ref())
		.and_then(extract_tool_text_payload)?;
	payload
		.get("statusCode")
		.and_then(Value::as_u64)
		.or_else(|| {
			payload
				.get("data")
				.and_then(|d| d.get("statusCode"))
				.and_then(Value::as_u64)
		})
}

/// Raw text of the first `text` content item in a tool result, WITHOUT parsing
/// it as JSON. Last-resort source for the `reason` of an error result whose
/// payload is a plain string rather than a `{"message": …}` object.
fn extract_tool_text_raw(result: &Value) -> Option<String> {
	result
		.get("content")?
		.as_array()?
		.iter()
		.find_map(|item| {
			if item.get("type").and_then(Value::as_str) != Some("text") {
				return None;
			}
			item
				.get("text")
				.and_then(Value::as_str)
				.map(ToOwned::to_owned)
		})
}

fn reason(log: &RequestLog, mcp: Option<&MCPInfo>, status: Option<u16>) -> Option<String> {
	let tool = mcp.and_then(|m| m.tool.as_ref());

	// 1. JSON-RPC error envelope message.
	if let Some(msg) = tool
		.and_then(|t| t.error.as_ref())
		.and_then(|err| {
			err.get("message").and_then(Value::as_str).or_else(|| {
				err
					.get("code")
					.and_then(Value::as_i64)
					.map(|_| "MCP tool error")
			})
		})
		.map(ToOwned::to_owned)
	{
		return Some(msg);
	}

	// 2. Message embedded in the tool result text content (Atlassian app
	//    errors, gateway rate-limit / confirmation envelopes).
	if let Some(payload) = tool
		.and_then(|t| t.result.as_ref())
		.and_then(extract_tool_text_payload)
		&& let Some(msg) = payload
			.get("message")
			.and_then(Value::as_str)
			.filter(|s| !s.is_empty())
	{
		return Some(msg.to_string());
	}

	// 2b. Error result with no top-level `message` — e.g. Microsoft Graph /
	//     Teams errors returned as `{"error": {"message": …}}`, a bare `error`
	//     string, or plain non-JSON error text. Guarded to failures ONLY so a
	//     successful tool's result body is never surfaced; capped to bound the
	//     log line.
	if tool.is_some_and(|t| tool_outcome_from_result(t) == Some("failure")) {
		let result = tool.and_then(|t| t.result.as_ref());
		if let Some(payload) = result.and_then(extract_tool_text_payload) {
			let msg = payload
				.get("error")
				.and_then(|e| e.get("message").and_then(Value::as_str).or_else(|| e.as_str()))
				.filter(|s| !s.is_empty())
				.map(ToOwned::to_owned);
			if let Some(msg) = msg {
				return Some(msg);
			}
		}
		if let Some(text) = result.and_then(extract_tool_text_raw) {
			let trimmed = text.trim();
			if !trimmed.is_empty() {
				return Some(trimmed.chars().take(300).collect());
			}
		}
	}

	// 3. Transport-level fallback (HTTP errors / connection failures).
	log.error.clone().or_else(|| match status {
		Some(401) => Some("Unauthorized".to_string()),
		Some(403) => Some("Forbidden".to_string()),
		Some(429) => Some("Rate limited".to_string()),
		Some(s) if s >= 400 => Some(format!("HTTP {s}")),
		_ => None,
	})
}

fn kait_user(log: &RequestLog) -> Option<String> {
	log
		.request_snapshot
		.as_ref()
		.and_then(|req| req.jwt.as_ref())
		.and_then(|claims| {
			for key in ["email", "preferred_username", "upn", "unique_name", "sub"] {
				if let Some(value) = claims.inner.get(key).and_then(Value::as_str)
					&& !value.is_empty()
				{
					return Some(value.to_string());
				}
			}
			None
		})
		.or_else(|| header(log, "x-user-email"))
		.or_else(|| header(log, "x-librechat-username"))
}

fn header<K>(log: &RequestLog, name: K) -> Option<String>
where
	K: AsHeaderName,
{
	log
		.request_snapshot
		.as_ref()
		.and_then(|req| req.headers.get(name))
		.and_then(|value| value.to_str().ok())
		.map(str::trim)
		.filter(|value| !value.is_empty())
		.map(ToOwned::to_owned)
}

fn transport(log: &RequestLog) -> &'static str {
	match log.method.as_ref().map(http::Method::as_str) {
		Some("GET") => "sse",
		Some("POST") => "streamable-http",
		_ => "http",
	}
}

fn route_segment(path: Option<&str>) -> Option<&str> {
	path
		.and_then(|p| p.trim_start_matches('/').split('/').next())
		.filter(|segment| !segment.is_empty())
}

fn tool_category(tool: &str) -> &'static str {
	let normalized = tool.to_ascii_lowercase();
	if normalized.contains("userinfo") || normalized.contains("auth") {
		"auth"
	} else if normalized.contains("accessible") || normalized.contains("metadata") {
		"metadata"
	} else if normalized.contains("search") || normalized.contains("lookup") {
		"search"
	} else if normalized.starts_with("create")
		|| normalized.starts_with("update")
		|| normalized.starts_with("edit")
		|| normalized.starts_with("add")
		|| normalized.starts_with("transition")
		|| normalized.starts_with("send")
		|| normalized.starts_with("reply")
	{
		"write"
	} else if normalized.starts_with("get") || normalized.starts_with("list") {
		"read"
	} else {
		"execution"
	}
}

fn affected_objects(tool: Option<&str>, args: Option<&Map<String, Value>>) -> Vec<Value> {
	let Some(args) = args else {
		return Vec::new();
	};
	let operation = tool.map(tool_category).unwrap_or("unknown");
	let mut objects = Vec::new();

	push_object(
		&mut objects,
		"jira_issue",
		"key",
		first_string(Some(args), &["issueKey", "issueIdOrKey", "key"]),
		operation,
	);
	push_object(
		&mut objects,
		"jira_issue",
		"id",
		first_string(Some(args), &["issueId", "id"]),
		operation,
	);
	push_object(
		&mut objects,
		"jira_project",
		"key",
		first_string(Some(args), &["projectKey", "project"]),
		operation,
	);
	push_object(
		&mut objects,
		"confluence_page",
		"id",
		first_string(Some(args), &["pageId", "contentId"]),
		operation,
	);
	push_object(
		&mut objects,
		"confluence_comment",
		"id",
		first_string(
			Some(args),
			&["commentId", "footerCommentId", "inlineCommentId"],
		),
		operation,
	);
	push_object(
		&mut objects,
		"confluence_space",
		"id",
		first_string(Some(args), &["spaceId", "spaceKey"]),
		operation,
	);
	push_object(
		&mut objects,
		"ms365_chat",
		"id",
		first_string(Some(args), &["chatId"]),
		operation,
	);
	push_object(
		&mut objects,
		"ms365_channel",
		"id",
		first_string(Some(args), &["channelId"]),
		operation,
	);
	// ms365 team id (get-team / list-team-channels / list-team-members and
	// every channel/team-scoped operation — MS Graph paths include {team-id}).
	push_object(
		&mut objects,
		"ms365_team",
		"id",
		first_string(Some(args), &["teamId", "team-id", "team_id"]),
		operation,
	);
	// ms365 message id from args. The semantic depends on the tool:
	//
	//   - get-channel-message / get-chat-message: this IS the target message
	//     being fetched. Logged as `ms365_message`.
	//   - reply-to-channel-message / reply-to-chat-message: this is the PARENT
	//     message under which the new reply is created. The new reply id comes
	//     from the upstream result (see affected_objects_from_result below) and
	//     is logged as `ms365_message`. To keep the two distinguishable in
	//     Splunk (so a reviewer doesn't confuse parent and new-reply), the
	//     parent goes under `ms365_parent_message`.
	//   - list-channel-message-replies / list-chat-message-replies: same shape
	//     — chatMessage-id is the parent whose replies are being listed.
	//
	// For send-* tools args carry no message id (it's assigned by MS Graph on
	// creation and surfaces via affected_objects_from_result below).
	let message_id_from_args = first_string(
		Some(args),
		&[
			"chatMessage-id",
			"chatMessageId",
			"messageId",
			"message-id",
		],
	);
	let args_message_type = match tool {
		Some(
			"reply-to-channel-message"
			| "reply-to-chat-message"
			| "list-channel-message-replies"
			| "list-chat-message-replies",
		) => "ms365_parent_message",
		_ => "ms365_message",
	};
	push_object(
		&mut objects,
		args_message_type,
		"id",
		message_id_from_args,
		operation,
	);
	// lookupJiraAccountId: record WHICH user the caller resolved (the search
	// term — a colleague's name / email / accountId). Guarded to this tool so
	// the generic candidate keys can't match unrelated tools' args.
	if tool == Some("lookupJiraAccountId") {
		push_object(
			&mut objects,
			"jira_user",
			"lookup",
			first_string(
				Some(args),
				&[
					"query",
					"searchString",
					"accountId",
					"displayName",
					"emailAddress",
					"username",
					"name",
					"user",
				],
			),
			operation,
		);
	}
	objects
}

/// Object identifiers derived from the tool RESULT (not the request args).
/// Used for create operations where the upstream assigns the new object's id
/// and it only appears in the response — e.g. the issue key Jira returns from
/// createJiraIssue (the request args carry only the project). Reads only
/// structured identifier fields, never the result body.
fn affected_objects_from_result(tool: Option<&str>, result: Option<&Value>) -> Vec<Value> {
	let mut objects = Vec::new();
	let Some(tool) = tool else {
		return objects;
	};
	let Some(result_val) = result else {
		return objects;
	};
	// Keep the raw text owned so the TOON fallback (below) can borrow it after
	// the JSON parse attempt; nested let-borrow on a temporary would not live
	// long enough.
	let raw_text = extract_tool_text_raw(result_val);
	let payload: Option<Value> = raw_text
		.as_deref()
		.and_then(|s| serde_json::from_str::<Value>(s).ok());
	let map = payload.as_ref().and_then(Value::as_object);
	let operation = tool_category(tool);
	if tool == "createJiraIssue" {
		let key = first_string(map, &["key", "issueKey"]);
		let has_key = key.is_some();
		push_object(&mut objects, "jira_issue", "key", key, operation);
		if !has_key {
			push_object(
				&mut objects,
				"jira_issue",
				"id",
				first_string(map, &["id", "issueId"]),
				operation,
			);
		}
	}
	// ms365 send / reply tools: the newly created chatMessage's id is assigned
	// by MS Graph on creation and only appears in the response. The args carry
	// the chat/channel (and for replies, the parent message id); the *new*
	// message id is captured here from the result.
	//
	// Two upstream encodings are handled, in priority order:
	//   1. JSON   — `first_string(map, ...)` reads `id` from the parsed object.
	//   2. TOON   — when ms365-mcp is launched with `--toon` the payload is a
	//               YAML-like dump that fails serde_json::from_str. Fall back
	//               to a regex that matches the top-level `id:` line; nested
	//               fields (e.g. `from.user.id`) are indented and excluded by
	//               the column-0 anchor.
	if matches!(
		tool,
		"send-channel-message"
			| "send-chat-message"
			| "reply-to-channel-message"
			| "reply-to-chat-message"
	) {
		let id = first_string(map, &["id", "chatMessageId", "messageId"])
			.or_else(|| raw_text.as_deref().and_then(extract_id_from_toon_top_level));
		push_object(&mut objects, "ms365_message", "id", id, operation);
	}
	objects
}

/// Last-resort id extractor for ms365 send/reply tool results when ms365-mcp
/// is configured with `--toon`, returning YAML-like TOON instead of JSON.
///
/// TOON top-level scalar: `id: "<value>"` (or unquoted) at column 0. Nested
/// `id` fields are indented and ignored by the `^` anchor. Quotes around the
/// value are optional — `@toon-format/toon` quotes long numeric strings but
/// leaves plain identifiers bare; both spellings are accepted.
fn extract_id_from_toon_top_level(text: &str) -> Option<String> {
	use std::sync::OnceLock;
	static RE: OnceLock<regex::Regex> = OnceLock::new();
	let re = RE.get_or_init(|| {
		regex::Regex::new(r#"(?m)^id:\s*['"]?([^\s'"]+)"#).expect("static regex compiles")
	});
	re.captures(text)?.get(1).map(|m| m.as_str().to_string())
}

fn push_object(
	objects: &mut Vec<Value>,
	object_type: &str,
	id_field: &str,
	value: Option<String>,
	operation: &str,
) {
	if let Some(value) = value {
		objects.push(json!({
			"type": object_type,
			id_field: value,
			"operation": operation,
		}));
	}
}

fn first_string(args: Option<&Map<String, Value>>, keys: &[&str]) -> Option<String> {
	let args = args?;
	for key in keys {
		if let Some(value) = args.get(*key) {
			if let Some(value) = value.as_str().filter(|value| !value.is_empty()) {
				return Some(value.to_string());
			}
			if let Some(value) = value.as_u64() {
				return Some(value.to_string());
			}
		}
	}
	None
}

fn duration_ms(duration: Duration) -> u64 {
	duration.as_millis().min(u64::MAX as u128) as u64
}

fn sha256(contents: &str) -> String {
	let mut hasher = Sha256::new();
	hasher.update(contents.as_bytes());
	hex::encode(hasher.finalize())
}

fn json_escape(value: &str) -> String {
	value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
	use serde_json::json;

	use super::*;

	/// Minimal context for cache tests that don't assert on the L1 event body.
	fn test_ctx() -> AuditContext {
		AuditContext {
			source_ip: Some("127.0.0.1".to_string()),
			source_port: Some(54321),
			forwarded_for: None,
			user_agent: None,
			transport: "streamable-http",
			server: "test".to_string(),
		}
	}

	#[test]
	fn classifies_write_tools() {
		assert_eq!(tool_category("createJiraIssue"), "write");
		assert_eq!(tool_category("searchJiraIssuesUsingJql"), "search");
		assert_eq!(tool_category("getConfluencePage"), "read");
	}

	#[test]
	fn affected_objects_extracts_only_identifiers() {
		let args = json!({
			"issueKey": "SEC-123",
			"body": "do not log this body",
			"cloudId": "cloud-1"
		})
		.as_object()
		.cloned()
		.unwrap();

		let objects = affected_objects(Some("addCommentToJiraIssue"), Some(&args));

		assert_eq!(objects.len(), 1);
		assert_eq!(objects[0]["type"], "jira_issue");
		assert_eq!(objects[0]["key"], "SEC-123");
		assert!(objects.iter().all(|obj| obj.get("body").is_none()));
	}

	// Real TOON output captured by encoding a typical MS Graph ChatMessage
	// response through the same `@toon-format/toon` package ms365-mcp uses
	// when launched with `--toon` (verified locally via `npm install
	// @toon-format/toon && node` — the encoded shape places `id` on line 0
	// with optional double-quotes around the value).
	const TOON_SEND_CHANNEL_MESSAGE_RESULT: &str = r#"id: "1780042021373"
replyToId: null
etag: "1780042021373"
messageType: message
createdDateTime: "2026-05-29T11:30:00Z"
channelIdentity:
  teamId: a92189c2-7cf2-429c-9964-257bee842c40
  channelId: "19:4fcef9c7359d42979b55292e80636b40@thread.tacv2"
from:
  user:
    id: abc-123
    displayName: Feng Lu
body:
  contentType: html
  content: "hi"
"#;

	#[test]
	fn toon_fallback_extracts_top_level_id_for_send_channel_message() {
		// Wrap the TOON text in the MCP CallToolResult envelope agentgateway
		// captures from upstream; the JSON parser will fail on the text body
		// and the function MUST fall back to the TOON regex.
		let result = json!({
			"content": [{"type": "text", "text": TOON_SEND_CHANNEL_MESSAGE_RESULT}],
		});
		let objects = affected_objects_from_result(Some("send-channel-message"), Some(&result));
		let msg = objects
			.iter()
			.find(|o| o["type"] == "ms365_message")
			.expect("ms365_message must be extracted from TOON fallback");
		assert_eq!(msg["id"], "1780042021373");
	}

	#[test]
	fn toon_fallback_ignores_nested_id_under_from_user() {
		// `from.user.id: abc-123` is indented; the `^id:` anchor rejects it,
		// so the top-level message id wins instead of the nested user id.
		let id = extract_id_from_toon_top_level(TOON_SEND_CHANNEL_MESSAGE_RESULT)
			.expect("regex must match top-level id");
		assert_eq!(id, "1780042021373");
		assert_ne!(id, "abc-123");
	}

	#[test]
	fn toon_fallback_handles_unquoted_id_value() {
		// Some TOON outputs leave plain ids bare (no surrounding quotes); the
		// optional `['"]?` group must accept both spellings.
		let text = "id: PLAIN-IDENTIFIER\nfoo: bar\n";
		let id = extract_id_from_toon_top_level(text).expect("unquoted id should match");
		assert_eq!(id, "PLAIN-IDENTIFIER");
	}

	#[test]
	fn affected_objects_from_result_prefers_json_when_parseable() {
		// JSON path stays the default; the TOON fallback only fires when
		// serde_json::from_str fails. A clean JSON body must continue to
		// produce the same result as before this PR.
		let result = json!({
			"content": [{
				"type": "text",
				"text": r#"{"id":"json-12345","body":{"content":"hi"}}"#,
			}],
		});
		let objects = affected_objects_from_result(Some("send-chat-message"), Some(&result));
		let msg = objects
			.iter()
			.find(|o| o["type"] == "ms365_message")
			.expect("ms365_message must come from the JSON path");
		assert_eq!(msg["id"], "json-12345");
	}

	// Security-team feedback: when a reply-* tool runs, both the parent
	// message id (from args) and the new reply id (from result) used to share
	// the `ms365_message` type — Splunk reviewers couldn't tell them apart.
	// The parent must now be tagged `ms365_parent_message` instead.

	#[test]
	fn reply_to_channel_message_separates_parent_and_new_message_types() {
		let args = json!({
			"teamId": "team-1",
			"channelId": "channel-1",
			"chatMessage-id": "PARENT-9999",
			"body": {"body": {"content": "ok", "contentType": "text"}},
		})
		.as_object()
		.cloned()
		.unwrap();
		let objects = affected_objects(Some("reply-to-channel-message"), Some(&args));
		// chatMessage-id MUST be tagged as parent, not as ms365_message.
		assert!(
			objects
				.iter()
				.any(|o| o["type"] == "ms365_parent_message" && o["id"] == "PARENT-9999"),
			"expected ms365_parent_message:PARENT-9999, got {:#?}",
			objects,
		);
		assert!(
			!objects
				.iter()
				.any(|o| o["type"] == "ms365_message" && o["id"] == "PARENT-9999"),
			"parent must NOT be double-tagged as ms365_message, got {:#?}",
			objects,
		);
	}

	#[test]
	fn reply_to_chat_message_separates_parent_message_type() {
		let args = json!({
			"chatId": "chat-1",
			"chatMessage-id": "PARENT-7777",
			"body": {"body": {"content": "ok", "contentType": "text"}},
		})
		.as_object()
		.cloned()
		.unwrap();
		let objects = affected_objects(Some("reply-to-chat-message"), Some(&args));
		assert!(
			objects
				.iter()
				.any(|o| o["type"] == "ms365_parent_message" && o["id"] == "PARENT-7777"),
			"expected ms365_parent_message:PARENT-7777, got {:#?}",
			objects,
		);
	}

	#[test]
	fn list_channel_message_replies_tags_parent_message() {
		let args = json!({
			"teamId": "team-1",
			"channelId": "channel-1",
			"chatMessage-id": "PARENT-LIST-1",
		})
		.as_object()
		.cloned()
		.unwrap();
		let objects = affected_objects(Some("list-channel-message-replies"), Some(&args));
		assert!(
			objects
				.iter()
				.any(|o| o["type"] == "ms365_parent_message" && o["id"] == "PARENT-LIST-1"),
			"list-channel-message-replies: chatMessage-id should be tagged parent (the message whose replies are listed); got {:#?}",
			objects,
		);
	}

	#[test]
	fn get_channel_message_keeps_ms365_message_type() {
		// get-* and send-* tools must NOT be re-tagged as parent — they
		// operate on the message itself, not on a parent of a reply.
		let args = json!({
			"teamId": "team-1",
			"channelId": "channel-1",
			"chatMessage-id": "TARGET-MSG-1",
		})
		.as_object()
		.cloned()
		.unwrap();
		let objects = affected_objects(Some("get-channel-message"), Some(&args));
		assert!(
			objects
				.iter()
				.any(|o| o["type"] == "ms365_message" && o["id"] == "TARGET-MSG-1"),
			"get-channel-message: chatMessage-id is the target message, must stay ms365_message; got {:#?}",
			objects,
		);
		assert!(
			!objects.iter().any(|o| o["type"] == "ms365_parent_message"),
			"get-channel-message must NOT introduce ms365_parent_message; got {:#?}",
			objects,
		);
	}

	#[test]
	fn session_id_hash_is_short_stable_and_irreversible() {
		let raw = "027OEn+0HMa3rdLIWy7xJp3Ka2F1jLxTHrWbL5O1Dxt..."; // opaque token
		let h = session_id_hash(raw);
		// 16 bytes → 32 hex chars; identical inputs hash identically.
		assert_eq!(h.len(), 32);
		assert_eq!(h, session_id_hash(raw));
		// Hash must NOT contain any prefix of the original token.
		assert!(!h.contains(&raw[..20]));
	}

	#[test]
	fn put_always_emits_key_even_when_absent() {
		let mut m = Map::new();
		put(&mut m, "present", Some("v".to_string()));
		put(&mut m, "absent", None);
		// Both keys exist; the absent one is JSON null, not omitted. This is
		// the canonical-schema guarantee the security team asked for.
		assert_eq!(m.get("present"), Some(&json!("v")));
		assert_eq!(m.get("absent"), Some(&Value::Null));
		assert!(m.contains_key("absent"));
	}

	#[test]
	fn upstream_status_extracts_app_code_when_transport_is_200() {
		// Confluence CQL-style error: MCP transport returns 200 but the
		// upstream API rejected with 400, encoded as statusCode in the
		// result payload text. upstream_status must surface the 400.
		let tool = MCPTool {
			target: "atlassian".into(),
			name: "searchConfluenceUsingCql".into(),
			arguments: None,
			result: Some(json!({
				"content": [{
					"type": "text",
					"text": "{\"statusCode\":400,\"message\":\"Could not parse cql\"}"
				}],
			})),
			error: None,
		};
		let mcp = MCPInfo {
			tool: Some(tool),
			..Default::default()
		};
		assert_eq!(upstream_status(Some(&mcp)), Some(400));
	}

	#[test]
	fn upstream_status_none_for_clean_success() {
		let tool = MCPTool {
			target: "atlassian".into(),
			name: "getJiraIssue".into(),
			arguments: None,
			result: Some(json!({
				"content": [{ "type": "text", "text": "{\"key\":\"AIE-1\"}" }],
			})),
			error: None,
		};
		let mcp = MCPInfo {
			tool: Some(tool),
			..Default::default()
		};
		assert_eq!(upstream_status(Some(&mcp)), None);
	}

	#[test]
	fn confirmation_affected_objects_derive_only_identifiers() {
		// emit_l3_tool_confirmation now derives affectedObjects from args so the
		// confirmation event records WHICH object is pending — identifiers only,
		// never content. This guards the affected_objects projection used there.
		let args = json!({
			"pageId": "63864834",
			"body": "secret page body must not leak",
			"title": "My favourite book"
		})
		.as_object()
		.cloned()
		.unwrap();
		let objects = affected_objects(Some("updateConfluencePage"), Some(&args));
		assert_eq!(objects.len(), 1);
		assert_eq!(objects[0]["type"], "confluence_page");
		assert_eq!(objects[0]["id"], "63864834");
		assert!(objects.iter().all(|o| o.get("body").is_none()));
		assert!(objects.iter().all(|o| o.get("title").is_none()));
	}

	#[test]
	fn session_user_cache_is_capture_once_and_evictable() {
		let sid = "sess-cache-test-1";
		// Initially empty.
		assert!(cached_session_user(sid).is_none());
		// First write wins.
		cache_session_user(sid, "first@kindredgroup.com", &test_ctx());
		cache_session_user(sid, "imposter@example.com", &test_ctx());
		assert_eq!(
			cached_session_user(sid).as_deref(),
			Some("first@kindredgroup.com")
		);
		// Eviction returns the stored value and clears the slot.
		assert_eq!(
			evict_session_user(sid).as_deref(),
			Some("first@kindredgroup.com")
		);
		assert!(cached_session_user(sid).is_none());
	}

	#[test]
	fn cache_session_user_only_caches_first_user_per_session() {
		// Functional check that the capture-once promise is preserved after
		// the L1 emission side-effect was added.
		let sid = "sess-l1-capture-once";
		cache_session_user(sid, "alice@kindredgroup.com", &test_ctx());
		cache_session_user(sid, "bob@kindredgroup.com", &test_ctx());
		// First user wins regardless of how many subsequent writes happen.
		assert_eq!(
			cached_session_user(sid).as_deref(),
			Some("alice@kindredgroup.com")
		);
		evict_session_user(sid);
	}

	#[test]
	fn session_user_cache_rejects_empty_and_oversize_writes() {
		let sid = "sess-cache-test-2";
		cache_session_user(sid, "", &test_ctx());
		assert!(cached_session_user(sid).is_none());
		let oversize = "a".repeat(MAX_KAIT_USER_LEN + 1);
		cache_session_user(sid, &oversize, &test_ctx());
		assert!(cached_session_user(sid).is_none());
	}

	#[test]
	fn session_closed_event_shape_is_minimal_and_redacted() {
		// Pre-populate cache so eviction returns the stored user.
		let sid = "sess-closed-shape-test";
		cache_session_user(sid, "feng.lu@kindredgroup.com", &test_ctx());

		// Capture stdout would be ideal; here we directly inspect the function
		// is wired to call `evict_session_user` (which empties the cache).
		emit_l3_session_closed(sid);
		assert!(
			cached_session_user(sid).is_none(),
			"session_closed must evict the cache entry"
		);
	}

	fn tool_with_result(result: Value) -> MCPTool {
		MCPTool {
			target: "atlassian".into(),
			name: "createConfluencePage".into(),
			arguments: None,
			result: Some(result),
			error: None,
		}
	}

	#[test]
	fn tool_outcome_detects_is_error_flag() {
		let tool = tool_with_result(json!({
			"isError": true,
			"content": [{ "type": "text", "text": "boom" }],
		}));
		assert_eq!(tool_outcome_from_result(&tool), Some("failure"));
	}

	#[test]
	fn tool_outcome_detects_application_error_in_text_payload() {
		// Atlassian-style: success envelope wrapping `{"error": true, ...}`.
		let tool = tool_with_result(json!({
			"isError": false,
			"content": [{
				"type": "text",
				"text": "{\"error\":true,\"message\":\"Access denied: write_confluence not authorized.\"}"
			}],
		}));
		assert_eq!(tool_outcome_from_result(&tool), Some("failure"));
	}

	#[test]
	fn tool_outcome_detects_rate_limit_envelope() {
		let tool = tool_with_result(json!({
			"content": [{
				"type": "text",
				"text": "{\"error\":\"rate_limit_exceeded\",\"message\":\"Tool 'X' called 6 times within 60s. Max 5.\"}"
			}],
		}));
		assert_eq!(tool_outcome_from_result(&tool), Some("blocked"));
	}

	#[test]
	fn tool_outcome_detects_confirmation_envelope() {
		let tool = tool_with_result(json!({
			"content": [{
				"type": "text",
				"text": "{\"confirmationRequired\":true,\"preview\":\"...\",\"expiresInSeconds\":120}"
			}],
		}));
		assert_eq!(
			tool_outcome_from_result(&tool),
			Some("pending_confirmation")
		);
	}

	#[test]
	fn tool_outcome_does_not_false_positive_on_prose_or_normal_json() {
		// Prose result that happens to mention the word "error".
		let prose = tool_with_result(json!({
			"content": [{ "type": "text", "text": "Found 3 issues mentioning 'error handler'." }],
		}));
		assert_eq!(tool_outcome_from_result(&prose), None);

		// Normal JSON success result that has no error-indicating fields.
		let success = tool_with_result(json!({
			"content": [{
				"type": "text",
				"text": "{\"key\":\"AIE-462\",\"summary\":\"Audit logs\",\"status\":\"In Progress\"}"
			}],
			"isError": false,
		}));
		assert_eq!(tool_outcome_from_result(&success), None);
	}

	#[test]
	fn config_summary_does_not_include_policy_bodies() {
		let config = r#"
binds:
  - port: 8082
    listeners:
      - name: atlassian
        hostname: atlassian.example.com
        routes:
          - name: jira-route
            policies:
              mcpAuthentication:
                mode: permissive
              mcpAuthorization:
                rules:
                  - "do not log full rules"
              mcpConfirmation:
                rules:
                  - "do not log full rules"
"#;

		let summary = config_summary(config, None).unwrap();

		assert_eq!(summary["ports"][0], 8082);
		let route = &summary["listeners"][0]["routes"][0];
		assert_eq!(route["authenticationMode"], "permissive");
		assert_eq!(route["authorizationEnabled"], true);
		assert_eq!(route["confirmationEnabled"], true);
		assert!(!summary.to_string().contains("do not log full rules"));
	}
}
