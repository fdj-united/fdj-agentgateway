use agent_core::strng;
use itertools::Itertools;
use serde::{Deserialize, Serialize};

use crate::http::auth::{AwsAuth, BackendAuth};
use crate::http::jwt::Claims;
use crate::llm::RequestType;
use crate::llm::bedrock::AwsRegion;
use crate::llm::policy::BedrockGuardrails;
use crate::proxy::httpproxy::PolicyClient;
use crate::types::agent::{BackendPolicy, ResourceName, SimpleBackend, Target};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GuardrailSource {
	/// Content from user input (requests)
	Input,
	/// Content from model output (responses)
	Output,
}

/// Text content block for guardrail evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardrailTextBlock {
	pub text: String,
}

/// Content block for guardrail evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct GuardrailContentBlock {
	pub text: GuardrailTextBlock,
}

/// Request body for ApplyGuardrail API
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ApplyGuardrailRequest {
	/// The source of the content (INPUT for requests, OUTPUT for responses)
	pub source: GuardrailSource,
	/// The content blocks to evaluate
	pub content: Vec<GuardrailContentBlock>,
}

/// Action taken by the guardrail
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GuardrailAction {
	/// No intervention needed
	None,
	/// Guardrail intervened — either blocked or masked/anonymized content
	GuardrailIntervened,
}

/// A sanitized content block returned by the guardrail when it masks
/// (anonymizes) input instead of blocking it.
#[derive(Debug, Clone, Deserialize)]
pub struct GuardrailOutputContent {
	pub text: String,
}

/// Response from ApplyGuardrail API.
///
/// The `action` field alone is ambiguous when the guardrail intervenes:
/// intervention can mean either "blocked" (whole request rejected) or
/// "masked" (per-entity anonymization). AWS returns an `outputs` array in
/// BOTH cases — for blocks it contains a canned "I can't help" style
/// message; for masks it contains the sanitized text. Presence of `outputs`
/// is therefore NOT a reliable discriminator (this was verified against the
/// real ApplyGuardrail API).
///
/// The reliable discriminator is per-entry `action` fields inside
/// `assessments`. Each policy entry (`contentPolicy.filters[]`,
/// `sensitiveInformationPolicy.piiEntities[]`, `wordPolicy.customWords[]`,
/// `topicPolicy.topics[]`, etc.) carries an `action` of `NONE`,
/// `BLOCKED`, or `ANONYMIZED`. If ANY entry anywhere in the assessments
/// tree carries `BLOCKED`, the whole response is a block; otherwise a
/// non-empty `outputs` array is safe to substitute back.
///
/// Assessments are stored as raw `Value` so we don't have to fully model
/// every AWS policy type and remain forward-compatible if AWS adds new
/// ones.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplyGuardrailResponse {
	/// The overall action taken by the guardrail.
	pub action: GuardrailAction,
	/// Human-readable reason, e.g. `"Guardrail masked."` or `"Guardrail blocked."`.
	#[serde(default)]
	pub action_reason: Option<String>,
	/// Sanitized content blocks. Present for both block AND mask responses;
	/// use [`is_blocked`] to disambiguate before consuming.
	#[serde(default)]
	pub outputs: Vec<GuardrailOutputContent>,
	/// Per-guardrail assessments. Kept as raw JSON — we walk for
	/// `"action": "BLOCKED"` to distinguish block from mask.
	#[serde(default)]
	pub assessments: Vec<serde_json::Value>,
}

impl ApplyGuardrailResponse {
	/// True when the guardrail truly blocked the content.
	///
	/// The primary discriminator is per-entry `action=BLOCKED` inside
	/// `assessments` — not the mere presence of the `outputs` field, which
	/// AWS populates for masks and blocks alike (a canned rejection string
	/// for blocks, sanitized text for masks).
	///
	/// As a defensive fallback, an intervened response with no sanitized
	/// outputs to forward is also treated as a block: there is nothing to
	/// substitute in and forwarding the empty text would silently drop the
	/// user's message.
	pub fn is_blocked(&self) -> bool {
		if self.action != GuardrailAction::GuardrailIntervened {
			return false;
		}
		if self.assessments.iter().any(Self::contains_blocked_action) {
			return true;
		}
		self.outputs.is_empty()
	}

	/// If the guardrail intervened by masking (anonymizing), returns the
	/// sanitized text for each input content block in order. Callers should
	/// substitute these back into the request/response and forward.
	///
	/// Returns None when the guardrail did not intervene, when it truly
	/// blocked (per [`is_blocked`]), or when no outputs were returned.
	pub fn masked_outputs(&self) -> Option<Vec<String>> {
		if self.action != GuardrailAction::GuardrailIntervened
			|| self.is_blocked()
			|| self.outputs.is_empty()
		{
			return None;
		}
		Some(self.outputs.iter().map(|o| o.text.clone()).collect())
	}

	/// Recursively walk a JSON value looking for any object with
	/// `{"action": "BLOCKED"}`. AWS uses the same string across policy
	/// types (content, sensitive info, word, topic, etc.), so this
	/// generic walk covers all of them without modelling each policy.
	fn contains_blocked_action(v: &serde_json::Value) -> bool {
		match v {
			serde_json::Value::Object(map) => {
				if let Some(s) = map.get("action").and_then(|v| v.as_str())
					&& matches!(s, "BLOCKED" | "BLOCK")
				{
					return true;
				}
				map.values().any(Self::contains_blocked_action)
			},
			serde_json::Value::Array(arr) => arr.iter().any(Self::contains_blocked_action),
			_ => false,
		}
	}
}

impl BedrockGuardrails {
	/// User-provided policies come first so they take precedence during resolution
	/// then system TLS and implicit AWS auth are appended as fallbacks.
	pub(crate) fn build_request_policies(&self) -> Vec<BackendPolicy> {
		let mut pols: Vec<BackendPolicy> = self.policies.to_vec();
		pols.push(BackendPolicy::BackendTLS(
			crate::http::backendtls::SYSTEM_TRUST.clone(),
		));
		pols.push(BackendPolicy::BackendAuth(BackendAuth::Aws(
			AwsAuth::Implicit {},
		)));
		pols
	}
}

/// Send a request to the Bedrock Guardrails ApplyGuardrail API for request content
pub async fn send_request(
	req: &mut dyn RequestType,
	claims: Option<Claims>,
	client: &PolicyClient,
	guardrails: &BedrockGuardrails,
) -> anyhow::Result<ApplyGuardrailResponse> {
	let content = req
		.get_messages()
		.into_iter()
		.map(|m| GuardrailContentBlock {
			text: GuardrailTextBlock {
				text: m.content.to_string(),
			},
		})
		.collect_vec();

	send_guardrail_request(
		client,
		claims.clone(),
		guardrails,
		GuardrailSource::Input,
		content,
	)
	.await
}

/// Send a request to the Bedrock Guardrails ApplyGuardrail API for response content
pub async fn send_response(
	content: Vec<String>,
	claims: Option<Claims>,
	client: &PolicyClient,
	guardrails: &BedrockGuardrails,
) -> anyhow::Result<ApplyGuardrailResponse> {
	let content = content
		.into_iter()
		.map(|text| GuardrailContentBlock {
			text: GuardrailTextBlock { text },
		})
		.collect_vec();

	send_guardrail_request(
		client,
		claims.clone(),
		guardrails,
		GuardrailSource::Output,
		content,
	)
	.await
}

async fn send_guardrail_request(
	client: &PolicyClient,
	claims: Option<Claims>,
	guardrails: &BedrockGuardrails,
	source: GuardrailSource,
	content: Vec<GuardrailContentBlock>,
) -> anyhow::Result<ApplyGuardrailResponse> {
	let request_body = ApplyGuardrailRequest { source, content };
	let host = strng::format!("bedrock-runtime.{}.amazonaws.com", guardrails.region);
	let path = format!(
		"/guardrail/{}/version/{}/apply",
		guardrails.guardrail_identifier, guardrails.guardrail_version
	);
	let uri = format!("https://{}{}", host, path);

	tracing::debug!(
		request_body = %serde_json::to_string_pretty(&request_body).unwrap_or_default(),
		uri = %uri,
		"Sending Bedrock guardrail request"
	);

	let pols = guardrails.build_request_policies();

	// AWS requires both Content-Type and Accept headers
	let mut rb = ::http::Request::builder()
		.uri(&uri)
		.method(::http::Method::POST)
		.header(::http::header::CONTENT_TYPE, "application/json")
		.header(::http::header::ACCEPT, "application/json")
		.extension(AwsRegion {
			region: guardrails.region.to_string(),
		});

	if let Some(claims) = claims {
		rb = rb.extension(claims);
	}

	let req = rb.body(crate::http::Body::from(serde_json::to_vec(&request_body)?))?;

	let mock_be = SimpleBackend::Opaque(
		ResourceName::new(strng::literal!("_bedrock-guardrails"), strng::literal!("")),
		Target::Hostname(host, 443),
	);

	let resp = client
		.call_with_explicit_policies(req, mock_be, pols)
		.await?;

	let status = resp.status();
	let lim = crate::http::response_buffer_limit(&resp);
	let (_, body) = resp.into_parts();
	let bytes = crate::http::read_body_with_limit(body, lim).await?;

	if !status.is_success() {
		let error_body = String::from_utf8_lossy(&bytes);
		tracing::warn!(
			status = %status,
			error_body = %error_body,
			guardrail_id = %guardrails.guardrail_identifier,
			"Bedrock guardrail API returned error"
		);
		anyhow::bail!(
			"Bedrock guardrail API error: status={}, body={}",
			status,
			error_body
		);
	}

	let resp: ApplyGuardrailResponse = serde_json::from_slice(&bytes)
		.map_err(|e| anyhow::anyhow!("Failed to parse Bedrock guardrail response: {e}"))?;

	match (resp.is_blocked(), resp.masked_outputs().is_some()) {
		(true, _) => tracing::debug!(
			guardrail_id = %guardrails.guardrail_identifier,
			guardrail_version = %guardrails.guardrail_version,
			source = ?source,
			"Bedrock guardrail blocked content"
		),
		(false, true) => tracing::debug!(
			guardrail_id = %guardrails.guardrail_identifier,
			guardrail_version = %guardrails.guardrail_version,
			source = ?source,
			"Bedrock guardrail masked content"
		),
		_ => {},
	}

	Ok(resp)
}
