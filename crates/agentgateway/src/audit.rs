use std::path::Path;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{SecondsFormat, Utc};
use http::header::AsHeaderName;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::mcp::MCPInfo;
use crate::telemetry::log::RequestLog;

const AUDIT_LEVEL: &str = "AUDIT";

// Defensive caps: any `Authorization` header beyond this is treated as untrusted
// junk; any decoded JWT payload beyond this is ignored. JWTs in practice are < 4KB.
const MAX_AUTHORIZATION_HEADER_BYTES: usize = 8 * 1024;
const MAX_JWT_PAYLOAD_BYTES: usize = 16 * 1024;

pub fn emit_l3_mcp_access(log: &RequestLog, mcp: Option<&MCPInfo>, duration: Duration) {
	let status = log.status.as_ref().map(|s| s.as_u16());
	let has_mcp_context = mcp.is_some_and(|m| !m.is_empty());
	let failed_auth = matches!(status, Some(401 | 403));

	if !has_mcp_context && !failed_auth {
		return;
	}

	let tool = mcp.and_then(|m| m.tool.as_ref());
	let args = tool.and_then(|t| t.arguments.as_ref());
	let tool_name = tool.map(|t| t.name.as_str());
	let server = mcp
		.and_then(|m| m.target_name())
		.or_else(|| route_segment(log.path.as_deref()))
		.unwrap_or("unknown");
	let outcome = access_outcome(status, log.error.as_deref(), mcp);
	let event_name = match (tool_name, outcome) {
		(Some(_), "denied") => "tool_call_denied",
		(Some(_), "blocked") => "tool_call_blocked",
		(Some(_), _) => "tool_call",
		(None, "denied") => "auth_failure",
		(None, _) => "mcp_access",
	};

	let mut event = audit_base("L3", event_name);
	put_opt(
		&mut event,
		"sessionId",
		mcp
			.and_then(|m| m.session_id.as_deref())
			.map(ToOwned::to_owned),
	);
	put_opt(&mut event, "kaitUser", kait_user(log));
	if let Some(identity) = atlassian_user(log, server) {
		event.insert("atlassianUser".into(), json!(identity));
		// Security spec requires both `atlassianUser` and `jiraUser` (alias).
		event.insert("jiraUser".into(), json!(identity));
	}
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

fn audit_base(logging_id: &'static str, event: &'static str) -> Map<String, Value> {
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

/// Returns the Atlassian-side user identity (email / preferred_username / opaque sub),
/// extracted from the upstream OAuth bearer token's claims. Only fires for
/// jira/confluence routes; other routes return `None`.
///
/// **The JWT signature is NOT verified.** The gateway's `mcpAuthentication: permissive`
/// mode does not always populate `req.jwt`, so we decode the raw `Authorization: Bearer`
/// header for audit purposes. The actual access decision is enforced by the upstream
/// Atlassian MCP server (which DOES verify signatures), so a forged claim here would
/// not grant access — it would only mislabel an `outcome=denied` audit event.
fn atlassian_user(log: &RequestLog, server: &str) -> Option<String> {
	if !matches!(server, "jira" | "confluence") {
		return None;
	}
	let claims = decode_authorization_bearer(log)?;
	[
		"email",
		"preferred_username",
		"https://api.atlassian.com/systemAccountEmail",
	]
	.into_iter()
	.filter_map(|k| claims.get(k).and_then(Value::as_str))
	.find(|v| !v.is_empty())
	.map(str::to_string)
	.or_else(|| {
		claims
			.get("sub")
			.and_then(Value::as_str)
			.filter(|v| !v.is_empty())
			.map(|sub| format!("atlassian:{sub}"))
	})
}

/// Decodes the JSON payload of a `Bearer <jwt>` `Authorization` header without
/// verifying the signature. Returns the claims as a JSON object.
///
/// Defensive: caps both input header size and decoded payload size to avoid
/// resource exhaustion on hostile tokens. Returns `None` on any parsing failure
/// rather than panicking — audit emission must never crash the gateway.
fn decode_authorization_bearer(log: &RequestLog) -> Option<Map<String, Value>> {
	let raw = header(log, "authorization")?;
	if raw.len() > MAX_AUTHORIZATION_HEADER_BYTES {
		return None;
	}
	let token = raw
		.strip_prefix("Bearer ")
		.or_else(|| raw.strip_prefix("bearer "))?
		.trim();
	let mut parts = token.split('.');
	let (_header, payload_b64, _signature) = (parts.next()?, parts.next()?, parts.next()?);
	if parts.next().is_some() {
		return None;
	}
	// Accept JWT payloads with or without `=` padding (both are seen in the wild).
	let payload = URL_SAFE_NO_PAD
		.decode(payload_b64.trim_end_matches('='))
		.ok()?;
	if payload.len() > MAX_JWT_PAYLOAD_BYTES {
		return None;
	}
	match serde_json::from_slice::<Value>(&payload).ok()? {
		Value::Object(map) => Some(map),
		_ => None,
	}
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

	/// Build a JWT-shaped string with the given JSON payload (signature is junk;
	/// our decoder never verifies it).
	fn jwt_with_payload(payload: &Value) -> String {
		let h = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
		let p = URL_SAFE_NO_PAD.encode(payload.to_string());
		format!("{h}.{p}.deadbeef")
	}

	fn decode_payload(token: &str) -> Option<Map<String, Value>> {
		let payload_b64 = token.split('.').nth(1)?;
		let payload = URL_SAFE_NO_PAD
			.decode(payload_b64.trim_end_matches('='))
			.ok()?;
		match serde_json::from_slice::<Value>(&payload).ok()? {
			Value::Object(map) => Some(map),
			_ => None,
		}
	}

	#[test]
	fn jwt_decode_extracts_whitelisted_claims_only() {
		let token = jwt_with_payload(&json!({
			"email": "feng.lu@kindredgroup.com",
			"sub": "5b10ac8d82e05b22cc7d4ef5",
			"scope": "read:jira-work",
			"do_not_log": "internal-secret",
		}));
		let claims = decode_payload(&token).expect("payload must parse");
		// Sanity: full claim object is parsed, but the caller picks only known fields.
		assert_eq!(claims["email"], "feng.lu@kindredgroup.com");
		assert_eq!(claims["sub"], "5b10ac8d82e05b22cc7d4ef5");
	}

	#[test]
	fn jwt_decode_returns_none_on_malformed_input() {
		// Empty payload portion.
		assert!(decode_payload("eyJ.. ").is_none());
		// Wrong number of segments.
		assert!(decode_payload("only.two").is_none());
		// Not base64.
		assert!(decode_payload("eyJ.@@@.sig").is_none());
	}

	#[test]
	fn atlassian_user_falls_back_to_sub_with_prefix() {
		let claims_email_present: Map<String, Value> = serde_json::from_value(json!({
			"email": "feng.lu@kindredgroup.com",
			"sub": "5b10ac8d82e05b22cc7d4ef5",
		}))
		.unwrap();
		let claims_sub_only: Map<String, Value> = serde_json::from_value(json!({
			"sub": "5b10ac8d82e05b22cc7d4ef5",
		}))
		.unwrap();

		// `email` is preferred when present.
		let email = claims_email_present
			.get("email")
			.and_then(Value::as_str)
			.unwrap();
		assert_eq!(email, "feng.lu@kindredgroup.com");

		// When only `sub` is available the audit field is prefixed `atlassian:` so
		// the opaque ID isn't mistaken for an email in Splunk.
		let sub_fallback = claims_sub_only
			.get("sub")
			.and_then(Value::as_str)
			.map(|s| format!("atlassian:{s}"))
			.unwrap();
		assert_eq!(sub_fallback, "atlassian:5b10ac8d82e05b22cc7d4ef5");
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
