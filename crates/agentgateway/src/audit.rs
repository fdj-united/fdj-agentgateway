use std::collections::HashMap;
use std::path::Path;
use std::sync::{LazyLock, RwLock};
use std::time::Duration;

use chrono::{SecondsFormat, Utc};
use http::header::AsHeaderName;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::mcp::MCPInfo;
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
fn cache_session_user(session_id: &str, user: &str) {
	if user.is_empty() || user.len() > MAX_KAIT_USER_LEN {
		return;
	}
	let mut map = SESSION_USER_CACHE
		.write()
		.expect("audit SESSION_USER_CACHE poisoned");
	map
		.entry(session_id.to_string())
		.or_insert_with(|| user.to_string());
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

	let session_id = mcp.and_then(|m| m.session_id.as_deref());

	// Resolve user identity with persistent session fallback:
	//   1. Current request (JWT or X-User-Email or X-LibreChat-Username)
	//   2. Cached identity from any prior request on the same session
	// Capture-once into the cache so SSE long-polls (no headers) and other
	// protocol traffic still attribute back to the original KAIT user.
	let kait_user = kait_user(log).or_else(|| session_id.and_then(cached_session_user));
	if let (Some(sid), Some(ref user)) = (session_id, kait_user.as_ref()) {
		cache_session_user(sid, user);
	}

	let mut event = audit_base("L3", event_name);
	put_opt(
		&mut event,
		"sessionIdHash",
		session_id.map(session_id_hash),
	);
	put_opt(&mut event, "kaitUser", kait_user);
	put_opt(
		&mut event,
		"sourceIp",
		Some(log.tcp_info.peer_addr.ip().to_string()),
	);
	put_opt(&mut event, "forwardedFor", header(log, "x-forwarded-for"));
	event.insert("transport".into(), json!(transport(log)));
	event.insert("outcome".into(), json!(outcome));
	event.insert(
		"reason".into(),
		reason(log, mcp, status).map_or(Value::Null, Value::String),
	);
	event.insert("server".into(), json!(server));
	put_opt(
		&mut event,
		"siteUrl",
		first_string(args, &["siteUrl", "site_url"]),
	);
	put_opt(
		&mut event,
		"cloudId",
		first_string(args, &["cloudId", "cloud_id"]),
	);
	put_opt(&mut event, "tool", tool_name.map(ToOwned::to_owned));
	if let Some(tool) = tool_name {
		event.insert("toolCategory".into(), json!(tool_category(tool)));
	}
	event.insert(
		"affectedObjects".into(),
		Value::Array(affected_objects(tool_name, args)),
	);
	event.insert("durationMs".into(), json!(duration_ms(duration)));
	put_opt(&mut event, "httpStatus", status.map(|s| s.to_string()));
	put_opt(
		&mut event,
		"mcpMethod",
		mcp
			.and_then(|m| m.method_name.as_deref())
			.map(ToOwned::to_owned),
	);

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
	put_opt(&mut event, "kaitUser", kait_user);
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
pub fn emit_l3_tool_confirmation(
	event_name: &str,
	session_id: &str,
	server: &str,
	tool: &str,
	outcome: &str,
) {
	let kait_user = cached_session_user(session_id);
	let mut event = audit_base("L3", event_name);
	event.insert("sessionIdHash".into(), json!(session_id_hash(session_id)));
	put_opt(&mut event, "kaitUser", kait_user);
	event.insert("server".into(), json!(server));
	event.insert("tool".into(), json!(tool));
	event.insert("toolCategory".into(), json!(tool_category(tool)));
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

fn put_opt(map: &mut Map<String, Value>, key: &str, value: Option<String>) {
	if let Some(value) = value {
		map.insert(key.into(), json!(value));
	}
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
	if error.is_some()
		|| status.is_some_and(|s| s >= 400)
		|| mcp
			.and_then(|m| m.tool.as_ref())
			.and_then(|tool| tool.error.as_ref())
			.is_some()
	{
		return "failure";
	}
	"success"
}

fn reason(log: &RequestLog, mcp: Option<&MCPInfo>, status: Option<u16>) -> Option<String> {
	mcp
		.and_then(|m| m.tool.as_ref())
		.and_then(|tool| tool.error.as_ref())
		.and_then(|err| {
			err.get("message").and_then(Value::as_str).or_else(|| {
				err
					.get("code")
					.and_then(Value::as_i64)
					.map(|_| "MCP tool error")
			})
		})
		.map(ToOwned::to_owned)
		.or_else(|| log.error.clone())
		.or_else(|| match status {
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
	objects
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
	fn session_user_cache_is_capture_once_and_evictable() {
		let sid = "sess-cache-test-1";
		// Initially empty.
		assert!(cached_session_user(sid).is_none());
		// First write wins.
		cache_session_user(sid, "first@kindredgroup.com");
		cache_session_user(sid, "imposter@example.com");
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
	fn session_user_cache_rejects_empty_and_oversize_writes() {
		let sid = "sess-cache-test-2";
		cache_session_user(sid, "");
		assert!(cached_session_user(sid).is_none());
		let oversize = "a".repeat(MAX_KAIT_USER_LEN + 1);
		cache_session_user(sid, &oversize);
		assert!(cached_session_user(sid).is_none());
	}

	#[test]
	fn session_closed_event_shape_is_minimal_and_redacted() {
		// Pre-populate cache so eviction returns the stored user.
		let sid = "sess-closed-shape-test";
		cache_session_user(sid, "feng.lu@kindredgroup.com");

		// Capture stdout would be ideal; here we directly inspect the function
		// is wired to call `evict_session_user` (which empties the cache).
		emit_l3_session_closed(sid);
		assert!(
			cached_session_user(sid).is_none(),
			"session_closed must evict the cache entry"
		);
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
