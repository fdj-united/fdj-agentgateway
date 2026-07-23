use axum::http::StatusCode;
use axum::response::Response;
use axum_core::response::IntoResponse;
use bytes::Bytes;
use http::Method;
use http::header::CONTENT_TYPE;
use http::uri::PathAndQuery;
use tracing::{debug, warn};

use crate::http::jwt::Claims;
use crate::http::oauth::{authorization_server_metadata_url, openid_configuration_metadata_url};
use crate::http::*;
use crate::json;
use crate::json::from_body_with_limit;
use crate::proxy::ProxyError;
use crate::proxy::httpproxy::PolicyClient;
use crate::types::agent::{McpAuthentication, McpIDP};

pub(crate) fn is_well_known_endpoint(path: &str) -> bool {
	path.starts_with("/.well-known/oauth-protected-resource")
		|| path.starts_with("/.well-known/oauth-authorization-server")
}

pub(super) async fn apply_token_validation(
	req: &mut Request,
	auth: &McpAuthentication,
) -> Result<(), ProxyError> {
	// skip well-known OAuth endpoints for authn
	if is_well_known_endpoint(req.uri().path()) {
		return Ok(());
	}
	let has_claims = req.extensions().get::<Claims>().is_some();

	if has_claims {
		// if mcp authn is configured but JWT already validated (claims exist from previous layer),
		// reject because we cannot validate MCP-specific auth requirements
		let err = ProxyError::ProcessingString(
			"MCP backend authentication configured but JWT token already validated and stripped by Gateway or Route level policy".to_string(),
		);
		return Err(create_auth_required_response(err, req, auth));
	}

	debug!(
		"MCP auth configured; validating Authorization header (mode={:?})",
		auth.mode
	);
	auth.jwt_validator.apply(None, req).await.map_err(|e| {
		create_auth_required_response(ProxyError::JwtAuthenticationFailure(e), req, auth)
	})?;
	Ok(())
}

pub(crate) async fn enforce_authentication(
	req: &mut Request,
	auth: &McpAuthentication,
	client: &PolicyClient,
) -> Result<Option<Response>, ProxyError> {
	let path = req.uri().path();
	// Skip JWT validation for well-known OAuth discovery endpoints and for the
	// token proxy path (which is reached before a token exists).
	let skip_validation = is_well_known_endpoint(path)
		|| (path.ends_with("/oauth/token") && auth.upstream_token_endpoint.is_some());
	if !skip_validation {
		apply_token_validation(req, auth).await?;
	}

	handle_mcp_request(req, auth, client).await
}

pub(crate) async fn handle_mcp_request(
	req: &mut Request,
	auth: &McpAuthentication,
	client: &PolicyClient,
) -> Result<Option<Response>, ProxyError> {
	match req.uri().path() {
		// TODO: indicate this is a DirectResponse
		path if path.ends_with("client-registration") => Ok(Some(
			client_registration(req, auth, client.clone())
				.await
				.map_err(|e| {
					warn!("client_registration error: {}", e);
					StatusCode::INTERNAL_SERVER_ERROR
				})
				.into_response(),
		)),
		path if path.starts_with("/.well-known/oauth-protected-resource") => Ok(Some(
			protected_resource_metadata(req, auth).await.into_response(),
		)),
		path if path.starts_with("/.well-known/oauth-authorization-server") => Ok(Some(
			authorization_server_metadata(req, auth, client.clone())
				.await
				.map_err(|e| {
					warn!("authorization_server_metadata error: {}", e);
					StatusCode::INTERNAL_SERVER_ERROR
				})
				.into_response(),
		)),
		path if path.ends_with("/oauth/token") && auth.upstream_token_endpoint.is_some() => {
			Ok(Some(
				token_proxy(req, auth, client.clone())
					.await
					.map_err(|e| {
						warn!("token_proxy error: {}", e);
						StatusCode::INTERNAL_SERVER_ERROR
					})
					.into_response(),
			))
		},
		_ => {
			// Not handled
			Ok(None)
		},
	}
}

pub(crate) fn create_auth_required_response(
	inner: ProxyError,
	req: &Request,
	auth: &McpAuthentication,
) -> ProxyError {
	let request_path = req.uri().path();
	// If the `resource` is explicitly configured, use that as the base. otherwise, derive it from the
	// the request URL
	let proxy_url = auth
		.resource_metadata
		.extra
		.get("resource")
		.and_then(|v| v.as_str())
		.and_then(|u| http::uri::Uri::try_from(u).ok())
		.and_then(|uri| {
			let mut parts = uri.into_parts();
			parts.path_and_query = Some(PathAndQuery::from_static(""));
			Uri::from_parts(parts).ok()
		})
		.and_then(|uri| uri.to_string().strip_suffix("/").map(ToString::to_string))
		.unwrap_or_else(|| get_redirect_url(req, request_path));
	let www_authenticate_value = format!(
		"Bearer resource_metadata=\"{proxy_url}/.well-known/oauth-protected-resource{request_path}\""
	);

	ProxyError::McpJwtAuthenticationFailure(Box::new(inner), www_authenticate_value)
}

pub(super) async fn protected_resource_metadata(
	req: &mut Request,
	auth: &McpAuthentication,
) -> Response {
	let new_uri = strip_oauth_protected_resource_prefix(req);

	// Determine the issuer to use - either use the same request URL and path that it was initially with,
	// or else keep the auth.issuer
	let issuer = if auth.provider.is_some() {
		// When a provider is configured, use the same request URL with the well-known prefix stripped
		strip_oauth_protected_resource_prefix(req)
	} else {
		// No provider configured, use the original issuer
		auth.issuer.clone()
	};

	let json_body = auth.resource_metadata.to_rfc_json(new_uri, issuer);

	::http::Response::builder()
		.status(StatusCode::OK)
		.header("content-type", "application/json")
		.header("access-control-allow-origin", "*")
		.header("access-control-allow-methods", "GET, OPTIONS")
		.header("access-control-allow-headers", "content-type")
		.body(axum::body::Body::from(Bytes::from(
			serde_json::to_string(&json_body).unwrap_or_default(),
		)))
		.unwrap_or_else(|_| {
			::http::Response::builder()
				.status(StatusCode::INTERNAL_SERVER_ERROR)
				.body(axum::body::Body::empty())
				.unwrap()
		})
}

fn get_redirect_url(req: &Request, strip_base: &str) -> String {
	let uri = req
		.extensions()
		.get::<filters::OriginalUrl>()
		.map(|u| u.0.clone())
		.unwrap_or_else(|| req.uri().clone());

	uri
		.path()
		.strip_suffix(strip_base)
		.map(|p| uri.to_string().replace(uri.path(), p))
		.unwrap_or(uri.to_string())
}

fn strip_oauth_protected_resource_prefix(req: &Request) -> String {
	let uri = req
		.extensions()
		.get::<filters::OriginalUrl>()
		.map(|u| u.0.clone())
		.unwrap_or_else(|| req.uri().clone());

	let path = uri.path();
	const OAUTH_PREFIX: &str = "/.well-known/oauth-protected-resource";

	// Remove the oauth-protected-resource prefix and keep the remaining path
	if let Some(remaining_path) = path.strip_prefix(OAUTH_PREFIX) {
		uri.to_string().replace(path, remaining_path)
	} else {
		// If the prefix is not found, return the original URI
		uri.to_string()
	}
}

pub(super) async fn authorization_server_metadata(
	req: &mut Request,
	auth: &McpAuthentication,
	client: PolicyClient,
) -> Result<Response, ProxyError> {
	// RFC 8414 URL for standard AS metadata. Keycloak does not implement RFC 8414; it only
	// exposes OpenID Provider Metadata at {issuer}/.well-known/openid-configuration (OIDC Discovery).
	let metadata_uri = match &auth.provider {
		Some(McpIDP::Keycloak { .. }) => openid_configuration_metadata_url(&auth.issuer),
		_ => authorization_server_metadata_url(&auth.issuer),
	};
	let ureq = ::http::Request::builder()
		.uri(metadata_uri)
		.body(Body::empty())?;
	let upstream = client.simple_call(ureq).await?;
	let limit = crate::http::response_buffer_limit(&upstream);
	let mut resp: serde_json::Value = from_body_with_limit(upstream.into_body(), limit)
		.await
		.map_err(ProxyError::Body)?;
	match &auth.provider {
		Some(McpIDP::Auth0 {}) => {
			// Auth0 does not support RFC 8707. We can workaround this by prepending an audience
			let Some(serde_json::Value::String(ae)) =
				json::traverse_mut(&mut resp, &["authorization_endpoint"])
			else {
				return Err(ProxyError::ProcessingString(
					"authorization_endpoint missing".to_string(),
				));
			};
			// If the user provided multiple audiences with auth0, just prepend the first one
			if let Some(aud) = auth.audiences.first() {
				ae.push_str(&format!("?audience={}", aud));
			}
		},
		Some(McpIDP::Keycloak { .. }) => {
			// Keycloak does not support RFC 8707.
			// We do not currently have a workload :-(
			// users will have to hardcode the audience.
			// https://github.com/keycloak/keycloak/issues/10169 and https://github.com/keycloak/keycloak/issues/14355

			// Keycloak doesn't do CORS for client registrations
			// https://github.com/keycloak/keycloak/issues/39629
			// We can workaround this by proxying it

			let current_uri = req
				.extensions()
				.get::<filters::OriginalUrl>()
				.map(|u| u.0.clone())
				.unwrap_or_else(|| req.uri().clone());
			let Some(serde_json::Value::String(re)) =
				json::traverse_mut(&mut resp, &["registration_endpoint"])
			else {
				return Err(ProxyError::ProcessingString(
					"registration_endpoint missing".to_string(),
				));
			};
			*re = format!("{current_uri}/client-registration");
		},
		_ => {},
	}

	// When a token proxy is configured, rewrite token_endpoint in the AS metadata to the
	// gateway-local path so LibreChat sends token requests here instead of directly to the IdP.
	// The path is {origin}{route_path}/oauth/token — e.g.
	//   request:  http://gateway:8085/.well-known/oauth-authorization-server/monday
	//   rewritten: http://gateway:8085/monday/oauth/token
	// This matches the extraMatches entry `exact: /monday/oauth/token` in the Helm config,
	// ensuring only the correct per-backend policy handles the request.
	if auth.upstream_token_endpoint.is_some() {
		let current_uri = req
			.extensions()
			.get::<filters::OriginalUrl>()
			.map(|u| u.0.clone())
			.unwrap_or_else(|| req.uri().clone());
		let path = current_uri.path();
		// Extract the route-path suffix that follows /.well-known/oauth-authorization-server
		// e.g. "/.well-known/oauth-authorization-server/monday" → "/monday"
		// e.g. "/.well-known/oauth-authorization-server"         → ""
		const AS_PREFIX: &str = "/.well-known/oauth-authorization-server";
		let route_suffix = path
			.strip_prefix(AS_PREFIX)
			.unwrap_or("")
			.to_string();
		// Build origin (scheme + authority, no path)
		let origin = {
			let mut parts = current_uri.clone().into_parts();
			parts.path_and_query = None;
			Uri::from_parts(parts)
				.ok()
				.map(|u| u.to_string())
				.unwrap_or_default()
				.trim_end_matches('/')
				.to_string()
		};
		let proxy_token_endpoint = format!("{origin}{route_suffix}/oauth/token");
		if let Some(te) = json::traverse_mut(&mut resp, &["token_endpoint"]) {
			*te = serde_json::Value::String(proxy_token_endpoint);
		}
	}

	let response = ::http::Response::builder()
		.status(StatusCode::OK)
		.header("content-type", "application/json")
		.header("access-control-allow-origin", "*")
		.header("access-control-allow-methods", "GET, OPTIONS")
		.header("access-control-allow-headers", "content-type")
		.body(axum::body::Body::from(Bytes::from(
			serde_json::to_string(&resp).map_err(|e| ProxyError::Body(crate::http::Error::new(e)))?,
		)))?;

	Ok(response)
}

pub(super) async fn client_registration(
	req: &mut Request,
	auth: &McpAuthentication,
	client: PolicyClient,
) -> Result<Response, ProxyError> {
	// Normalize issuer URL by removing trailing slashes to avoid double-slash in path
	let issuer = auth.issuer.trim_end_matches('/');
	let body = std::mem::take(req.body_mut());
	let ureq = ::http::Request::builder()
		.uri(format!("{issuer}/clients-registrations/openid-connect"))
		.method(Method::POST)
		.body(body)?;

	let mut upstream = client.simple_call(ureq).await?;

	// Add CORS headers to the response
	let headers = upstream.headers_mut();
	headers.insert("access-control-allow-origin", "*".parse().unwrap());
	headers.insert(
		"access-control-allow-methods",
		"POST, OPTIONS".parse().unwrap(),
	);
	headers.insert(
		"access-control-allow-headers",
		"content-type".parse().unwrap(),
	);

	Ok(upstream)
}

/// Proxy a token request to the upstream IdP, rewriting the `resource` parameter so the
/// upstream mints a token with the correct audience rather than the gateway's own URL.
pub(super) async fn token_proxy(
	req: &mut Request,
	auth: &McpAuthentication,
	client: PolicyClient,
) -> Result<Response, ProxyError> {
	let Some(upstream_token_endpoint) = &auth.upstream_token_endpoint else {
		return Err(ProxyError::ProcessingString(
			"upstream_token_endpoint not configured".to_string(),
		));
	};

	let limit = crate::http::buffer_limit(req);
	let body_bytes = crate::http::read_body_with_limit(std::mem::take(req.body_mut()), limit)
		.await
		.map_err(ProxyError::Body)?;

	// Parse application/x-www-form-urlencoded body and rewrite `resource` if configured
	let rewritten: Bytes = if let Some(upstream_resource) = &auth.upstream_resource {
		let mut params: Vec<(String, String)> =
			serde_urlencoded::from_bytes(&body_bytes).unwrap_or_default();
		if let Some(pos) = params.iter().position(|(k, _)| k == "resource") {
			params[pos].1 = upstream_resource.clone();
		} else {
			params.push(("resource".to_string(), upstream_resource.clone()));
		}
		Bytes::from(serde_urlencoded::to_string(&params).unwrap_or_default())
	} else {
		body_bytes
	};

	let mut rb = ::http::Request::builder()
		.uri(upstream_token_endpoint.as_str())
		.method(Method::POST)
		.header(CONTENT_TYPE, "application/x-www-form-urlencoded");
	// Forward client auth headers (e.g. Authorization: Basic ... for client_secret_basic).
	if let Some(auth_val) = req.headers().get(::http::header::AUTHORIZATION) {
		rb = rb.header(::http::header::AUTHORIZATION, auth_val);
	}
	let ureq = rb.body(axum::body::Body::from(rewritten))?;

	let mut upstream = client.simple_call(ureq).await?;

	let headers = upstream.headers_mut();
	headers.insert("access-control-allow-origin", "*".parse().unwrap());
	headers.insert(
		"access-control-allow-methods",
		"POST, OPTIONS".parse().unwrap(),
	);
	headers.insert(
		"access-control-allow-headers",
		"content-type".parse().unwrap(),
	);

	Ok(upstream)
}
