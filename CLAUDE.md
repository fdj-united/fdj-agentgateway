# kindred-mcp-gateway — orientation for Claude

This is the helm chart for a standalone deployment of **agentgateway** that fronts internal MCP servers for KAIT (LibreChat).

## What lives where

| Repo / path | Owner | Purpose |
|---|---|---|
| `bitbucket:DDE/kindred-mcp-gateway` (this) | DDE | Helm chart (templates + default values) |
| `bitbucket:DDE/dev-tools/kindred-mcp-gateway` (`dev.tools/kindred-mcp-gateway/` locally) | DDE | Per-env config: values override + SealedSecret. ArgoCD watches it. |
| `github.com/fdj-united/fdj-agentgateway` (`agentgateway/` locally) | DDE | Our fork of agentgateway with `mcpRateLimit` / `mcpConfirmation` / `mcpArgRewrite`. Image: `ghcr.io/fdj-united/agentgateway:v0.0.7`. |
| `bitbucket:MCP/ms365-mcp` (`ms365-mcp/` locally) | DDE | Upstream MS Graph MCP server — gateway proxies `/teams` / `/other` to it. Branch `rev/removing-guardrails` is the relevant one. |
| `bitbucket:DEPLOY/si1/librechat` (`si1/librechat/` locally) | DDE | Prod LibreChat env config — references gateway URLs as MCP servers. |
| `Fdj-LibreChat/` (locally) | DDE | LibreChat fork — used for local dev + future client-side MCP confirmation work. |

## Traffic shape

```
Browser / KAIT pod (si1)
    → envoy edge (10.98.25.197)               # corp internal, wildcard *.kindredgroup.com cert
    → traefik-internal (dev.tools cluster)
    → nginx-internal Ingress
    → agentgateway pod
    → upstream MCP servers (ms365-mcp-dev, mcp.atlassian.com)
```

DNS: `*.mcp-gateway-dev.kindredgroup.com` is internal-only (split-horizon, RFC1918). Wildcard LE cert auto-renewed via DNS-01.

## Listeners + backends (current state)

| Listener (port) | Hostname | Backend (path) | Upstream | Auth model |
|---|---|---|---|---|
| `ms365` (8081) | `ms365.mcp-gateway-dev.kindredgroup.com` | `/teams` | `https://ms365-mcp-dev.kindredgroup.com/mcp` | Static Bearer (Graph token from LibreChat) |
| `ms365` (8081) | same | `/other` | same | same |
| `atlassian` (8082) | `atlassian.mcp-gateway-dev.kindredgroup.com` | `/jira` | `https://mcp.atlassian.com/v1/mcp` | OAuth (`mcpAuthentication: permissive`) |
| `atlassian` (8082) | same | `/confluence` | same | OAuth (`mcpAuthentication: permissive`) |

For OAuth backends: `extraMatches` MUST include `/.well-known/oauth-protected-resource/<path>` and `/.well-known/oauth-authorization-server/<path>` so the gateway serves OAuth metadata.

## Admin UI

- Hostname: `admin.mcp-gateway-dev.kindredgroup.com`
- Behind oauth2-proxy sidecar (Entra OIDC, tenant `82ff090d-4ac0-439f-834a-0c3f3d5f33ce`)
- Entra app: `MCP Gateway`, client ID `205d2c66-5ecc-4554-9280-0c4479c2965f`, secret in Keeper
- Container port `4180` (oauth2-proxy) → reverse-proxies to `127.0.0.1:15000` (agentgateway admin loopback)
- Service exposes `4180` (no longer `15000`)
- Admin Ingress needs **bigger nginx buffers** because Entra ID cookies are large — annotations already set in env config

## Known traps (read these before debugging)

1. **musl-libc resolver strictness on Alpine** — LibreChat is Alpine; an AAAA `SERVFAIL` from upstream DNS causes `getaddrinfo EAI_AGAIN` and 5-s timeouts. We hit this when the new `mcp-gateway-dev` zone was set up; fixed by the DNS team. Rule of thumb: any new zone must return `NOERROR/NODATA` for AAAA, not `SERVFAIL`.

2. **`mcpAuthentication` modes** — `strict` rejects mismatched audiences (Atlassian's `aud` is `cf.mcp.atlassian.com`, MS Graph's is `00000003-0000-0000-c000-000000000000` for v1 / `https://graph.microsoft.com` for v2). Use `permissive` when you only want metadata generation, not real validation. Atlassian metadata is served from `mcp.atlassian.com/.well-known/oauth-authorization-server` (not from the issuer URL — Atlassian breaks RFC 8414).

3. **OAuth in LibreChat** — for OAuth-protected MCP servers, **don't set an `Authorization` header** in the LibreChat `headers:` block. It short-circuits OAuth discovery. Use only the `oauth:` block with `scope:`. For static-Bearer servers (Ms-Teams), the headers block is correct.

4. **`{{LIBRECHAT_USER_EMAIL}}` substitution doesn't fire on OAuth-flow code paths** — the placeholder reaches the wire literally. Use `jwt.email` in the gateway access log CEL with `request.headers["X-User-Email"]` as a fallback.

5. **HTTP vs HTTPS upstream** — backend `mcp.host` must be `https://` for `nginx-internal`-fronted upstreams. We've regressed on this multiple times. Symptom: JSON-RPC `-32603 "failed ..."` errors with truncated message.

6. **`mcpConfirmation` is a soft guard** — agent (LLM) decides whether to honor the instruction. PoC bypass demonstrated. Real fix is in **LibreChat client-side** (intercept `confirmationRequired` responses, present modal, block agent loop until user clicks). Implemented in `Fdj-LibreChat/client/src/components/MCP/MCPConfirmationDialog.tsx`; the LibreChat backend wrapper sits in `api/server/services/MCP.js` and `packages/api/src/mcp/ConfirmationStore.ts`. The gateway optionally attaches a `presentation` block to the confirmation envelope — see "Confirmation envelope contract" below.

7. **macOS keychain + agentgateway native run** — rustls-native-certs panics on `BadEncoding` in some keychain certs (Zscaler). Fork patched at `crates/agentgateway/src/http/backendtls.rs:165` to use `add_parsable_certificates` instead of `add().unwrap()`. **Side effect**: Zscaler cert gets *skipped*, so any TLS to Zscaler-intercepted endpoints (e.g. JWKS fetch to `auth.atlassian.com`) fails. Workaround: drop `mcpAuthentication` blocks from local-dev config — JWKS fetch never happens.

## Local dev

Two scripts in `scripts/`:

- **`run-local.sh`** — Docker. Quick to start but hits VPN-DNS isolation problems (Docker Desktop on macOS doesn't inherit corp VPN DNS).
- **`run-local-native.sh`** — Native cargo build + run. Uses host network → no DNS issues. First build is slow (~5-10 min); subsequent runs use cached binary unless `.rs` files changed.

Both publish:
- `8081` Ms-Teams listener
- `8082` Atlassian listener
- `15000` admin UI (no oauth2-proxy locally)
- `15020` Prometheus
- `15021` readiness

Local LibreChat (in `Fdj-LibreChat/`) connects via `librechat.yaml` pointing at `http://localhost:8081/teams` etc. For OAuth-protected MCP servers locally: paste a static Bearer from a prior prod OAuth flow into the headers block — agentgateway local doesn't have OAuth metadata serving (we drop `mcpAuthentication` to avoid the JWKS-fetch-via-Zscaler problem).

## Recent significant changes (history matters)

- **2026-04-30** — Standalone gateway deployed; ms365 + atlassian initial paths.
- **2026-05-01** — Tracked AAAA SERVFAIL DNS bug to its source; DNS team fixed.
- **2026-05-04** — Added `extraMatches` for OAuth well-known paths; required for path-based Atlassian split.
- **2026-05-05** — `mcpAuthentication` template added to chart; `permissive` mode chosen for Atlassian (audience mismatch with strict).
- **2026-05-06** — `oauth2-proxy` sidecar added for admin UI; `socat` sidecar removed; SealedSecret for Entra credentials.
- **2026-05-07** — Security review; `ms365-mcp` guardrails confirmed removed in `rev/removing-guardrails` branch (closes JWT-spoof vector); gateway-side `mcpAuthentication: strict` for ms365 attempted but rejected as too brittle (audience varies between v1/v2 tokens).
- **2026-05-08** — Local-dev scripts; macOS keychain TLS panic patched; LibreChat client-side confirmation dialog work begun.

## Outstanding work / open questions

- **LibreChat client-side confirmation dialog** — in progress in `Fdj-LibreChat/client/src/components/MCP/MCPConfirmationDialog.tsx`. Closes the `mcpConfirmation` bypass.
- **NetworkPolicy for ms365-mcp** — restrict ingress so only the gateway can reach it (closes "skip the gateway, hit ms365-mcp directly" bypass).
- **Per-user `mcpRateLimit`** — currently per-session. Upstream contribution opportunity.
- **MCP elicitation protocol** — long-term replacement for confirmation soft-guard pattern.
- **Patch agentgateway to honor `SSL_CERT_FILE`** — for the macOS local-dev case where Zscaler intercepts JWKS fetches.

## Useful one-liners

```sh
# Verify deployed config matches local
helm template test ./helm --values /Users/romy/Documents/dev.tools/kindred-mcp-gateway/config/default.yaml

# Inspect a Microsoft Graph token (paste full JWT into TOKEN)
node -e 'const [,p]=process.env.TOKEN.split("."); console.log(JSON.parse(Buffer.from(p,"base64").toString()))'

# kubectl into dev.tools
export KUBECONFIG=$HOME/.kube/dev-tools.conf   # readonly_user.conf from kubernetes-configuration repo

# kubectl into si1 (LibreChat lives here)
export KUBECONFIG=$HOME/.kube/si1.conf

# Splunk: per-user audit trail
index=pe_dev_tools_k8s namespace=kindred-mcp-gateway user="someone@kindredgroup.com"
```

## Don't

- Don't add `mcpAuthentication: strict` for MS Graph without first decoding a real token (audience varies v1/v2)
- Don't put the client-secret value in `default.yaml` — it goes in `secrets.yaml` (SealedSecret)
- Don't bypass `mcpConfirmation` by changing the gateway — fix it in LibreChat client
- Don't use plain HTTP for `mcp.host` — `nginx-internal`-fronted upstreams are HTTPS only
- Don't propagate `X-User-Email` header trust into upstream services — derive identity from verified `jwt.email` instead

## Confirmation envelope contract

When `mcpConfirmation` matches, the gateway returns a tool result whose first text content is a JSON envelope:

```json
{
  "confirmationRequired": true,
  "preview": "Tool: send-chat-message\n  chatId: \"19:...\"\n  body: {...}",
  "expiresInSeconds": 120,
  "instruction": "STOP. Do NOT re-call this tool automatically. ...",
  "presentation": {
    "title": "Send Teams message",
    "summary": "Send a chat message to a Teams conversation",
    "fields": [
      { "label": "To",      "value": "19:abc...",       "format": "code", "importance": "primary" },
      { "label": "Message", "value": "Have a nice day", "format": "text", "importance": "primary" },
      { "label": "Format",  "value": "text",            "format": "code", "importance": "detail"  }
    ]
  }
}
```

The LibreChat client **never shows this envelope to the LLM** — it intercepts, suspends the agent loop, and renders either:

1. `presentation` (preferred): structured key-value rows, with `detail` fields collapsed under "Show more".
2. `preview` (fallback): the raw block string, parsed line-by-line on the client.

### Configuring `presentation` per tool

Inside an `mcpConfirmation` policy block, add `presentations:` — a list of rules. The first rule whose `tools` list includes the incoming tool's short name wins. Field values are projected from the call arguments via dot-paths (same syntax as `mcpArgRewrite.path`); missing paths drop silently.

```yaml
- mcpConfirmation:
    matcher: '... CEL deciding which tools require confirmation ...'
    ttlSeconds: 120
    presentations:
      - tools: [send-chat-message]
        title: "Send Teams message"
        summary: "Send a chat message to a Teams conversation"
        fields:
          - label: "To"
            path: "chatId"
            format: code           # text | code | json | markdown
            importance: primary    # primary | detail
          - label: "Message"
            path: "body.content"
            format: text
            importance: primary
          - label: "Format"
            path: "body.contentType"
            format: code
            importance: detail
```

### Design notes

- This is **modelled on, not aligned with, MCP elicitation** (https://modelcontextprotocol.io/specification/2025-06-18/client/elicitation). Elicitation is for *requesting* user input; we're *previewing* an action. When elicitation lands as a real protocol message, this becomes one of two channels (preview-and-confirm vs collect-and-submit) the client surfaces.
- The contract is **purely additive** — old envelopes without `presentation` still render via the legacy `preview` parser. Roll out per tool at your own pace.
- If every field path misses, the gateway omits the `presentation` entirely so the client falls back to `preview` instead of showing an empty card.
- Tests live at `crates/agentgateway/src/mcp/rbac.rs` (`presentation_tests` module) and `Fdj-LibreChat/packages/api/src/mcp/__tests__/ConfirmationStore.test.ts` (`presentation field` describe block).
