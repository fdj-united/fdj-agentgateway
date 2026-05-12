#!/usr/bin/env bash
# Run the kindred-mcp-gateway locally in Docker for end-to-end testing.
#
#   - Renders the helm chart against a local-only values file (no oauth2-proxy,
#     no TLS, no SealedSecrets — admin UI exposed plaintext on localhost).
#   - Extracts just the agentgateway config block from the rendered manifests.
#   - Runs the agentgateway image (Kindred fork — has mcpRateLimit/Confirmation/
#     ArgRewrite contributions baked in) with all listener + admin + metrics
#     ports published to localhost.
#
# Usage:
#   ./scripts/run-local.sh           # start
#   ./scripts/run-local.sh stop      # stop + cleanup
#   ./scripts/run-local.sh logs      # tail logs
#   ./scripts/run-local.sh shell     # open a debugging shell in the container
#
# Prereqs: docker, helm, ruby (for YAML sanity check), python3

set -euo pipefail

# ──────────────────────────────────────────────────────────────────────────────
# Config — adjust as needed
# ──────────────────────────────────────────────────────────────────────────────
CONTAINER_NAME="kindred-mcp-gateway-local"
IMAGE="ghcr.io/fdj-united/agentgateway:v0.0.7"

# Listener ports → what the chart emits in `listeners[].port`
TEAMS_PORT=8081
ATLASSIAN_PORT=8082

# Built-in agentgateway ports
ADMIN_PORT=15000        # admin UI + config API
STATS_PORT=15020        # Prometheus metrics
READINESS_PORT=15021    # readiness probe

# Where to write intermediate files
WORK_DIR="${TMPDIR:-/tmp}/kindred-mcp-gateway-local"
CHART_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/helm"
VALUES_FILE="$WORK_DIR/local-values.yaml"
RENDERED_FILE="$WORK_DIR/rendered.yaml"
CONFIG_FILE="$WORK_DIR/config.yaml"

# Subcommands ────────────────────────────────────────────────────────────────
case "${1:-start}" in
  stop)
    docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
    echo "Stopped $CONTAINER_NAME"
    exit 0
    ;;
  logs)
    docker logs -f "$CONTAINER_NAME"
    exit 0
    ;;
  shell)
    docker exec -it "$CONTAINER_NAME" sh
    exit 0
    ;;
  start) ;;
  *)
    echo "Usage: $0 {start|stop|logs|shell}"
    exit 1
    ;;
esac

# ──────────────────────────────────────────────────────────────────────────────
# 1. Build a local-friendly values file
# ──────────────────────────────────────────────────────────────────────────────
mkdir -p "$WORK_DIR"
cat > "$VALUES_FILE" <<EOF
image:
  registry: ghcr.io/fdj-united
  repository: agentgateway
  tag: "v0.0.7"

# No ingress, no TLS — agentgateway runs plain HTTP locally.
# Admin UI is exposed without oauth2-proxy (loopback-ish via Docker port publish).
ingress:
  enabled: false
admin:
  enabled: false   # we publish :15000 directly via docker -p

cors:
  allowOrigins: ["*"]
  allowHeaders: ["mcp-protocol-version", "content-type", "cache-control", "Accept", "Authorization", "X-User-Email"]

frontendPolicies:
  accessLog:
    user: 'request.headers["X-User-Email"]'

listeners:
  # ─── Microsoft 365 / Teams ──────────────────────────────────────────────
  # NOTE: upstream ms365-mcp-dev.kindredgroup.com is internal-only —
  # you must be on the corp VPN for actual Graph calls to work.
  - name: ms365
    port: $TEAMS_PORT
    backends:
      - name: teams
        routePath: /teams
        mcp:
          host: https://ms365-mcp-dev.kindredgroup.com/mcp
          insecureTLS: true   # dev-only;
        argRewrite:
          - tools: [send-chat-message, send-channel-message, reply-to-chat-message, reply-to-channel-message]
            path: body.body.content
            op: append
            value: "<br><br><i>— Sent via KAIT (LOCAL DEV)</i>"
        confirmation:
          ttlSeconds: 120
          rules:
            - 'mcp.tool.name in ["send-chat-message", "send-channel-message", "reply-to-chat-message", "reply-to-channel-message"]'
        rateLimit:
          maxCalls: 5
          windowSeconds: 60
          rules:
            - 'mcp.tool.name in ["send-chat-message"]'
        authorization:
          - 'mcp.tool.name in ["get-team", "list-joined-teams", "list-team-channels", "get-team-channel", "list-team-members", "list-channel-messages", "get-channel-message", "list-channel-message-replies", "reply-to-channel-message", "send-channel-message", "list-chats", "get-chat", "list-chat-messages", "get-chat-message", "list-chat-message-replies", "reply-to-chat-message", "send-chat-message"]'

  # ─── Atlassian (Jira + Confluence split) ────────────────────────────────
  # Public upstream — works without VPN.
  - name: atlassian
    port: $ATLASSIAN_PORT
    backends:
      - name: jira
        routePath: /jira
        extraMatches:
          - exact: /.well-known/oauth-protected-resource/jira
          - exact: /.well-known/oauth-authorization-server/jira
        mcp:
          host: https://mcp.atlassian.com/v1/mcp
        confirmation:
          ttlSeconds: 120
          rules:
            - 'mcp.tool.name in ["createJiraIssue", "editJiraIssue", "transitionJiraIssue", "addCommentToJiraIssue"]'
        authorization:
          - 'mcp.tool.name in ["atlassianUserInfo", "getAccessibleAtlassianResources", "getJiraIssue", "editJiraIssue", "createJiraIssue", "getTransitionsForJiraIssue", "transitionJiraIssue", "lookupJiraAccountId", "searchJiraIssuesUsingJql", "addCommentToJiraIssue", "getJiraIssueRemoteIssueLinks", "getVisibleJiraProjects", "getJiraProjectIssueTypesMetadata"]'

      - name: confluence
        routePath: /confluence
        extraMatches:
          - exact: /.well-known/oauth-protected-resource/confluence
          - exact: /.well-known/oauth-authorization-server/confluence
        mcp:
          host: https://mcp.atlassian.com/v1/mcp
        confirmation:
          ttlSeconds: 120
          rules:
            - 'mcp.tool.name in ["createConfluencePage", "updateConfluencePage", "createConfluenceFooterComment", "createConfluenceInlineComment"]'
        authorization:
          - 'mcp.tool.name in ["atlassianUserInfo", "getAccessibleAtlassianResources", "createConfluenceFooterComment", "createConfluenceInlineComment", "createConfluencePage", "getConfluencePage", "getConfluencePageDescendants", "getConfluencePageFooterComments", "getConfluencePageInlineComments", "getConfluenceSpaces", "getPagesInConfluenceSpace", "searchConfluenceUsingCql", "updateConfluencePage"]'
EOF

# ──────────────────────────────────────────────────────────────────────────────
# 2. Render the chart and extract just the agentgateway config block
# ──────────────────────────────────────────────────────────────────────────────
helm template local "$CHART_DIR" --values "$VALUES_FILE" > "$RENDERED_FILE"

python3 - "$RENDERED_FILE" "$CONFIG_FILE" <<'PY'
import re, sys
src, dst = sys.argv[1], sys.argv[2]
text = open(src).read()
m = re.search(r'config\.yaml: \|\n((?:    .*\n|\n)+)', text)
if not m:
    sys.exit("FAIL: could not find config.yaml in rendered helm output")
inner = m.group(1)
cleaned = '\n'.join(line[4:] if line.startswith('    ') else line for line in inner.splitlines())
open(dst, 'w').write(cleaned + '\n')
PY

# Validate it's parseable YAML before handing to agentgateway
ruby -ryaml -e 'YAML.load_file(ARGV[0])' "$CONFIG_FILE" >/dev/null

echo "✓ Config rendered to $CONFIG_FILE"

# ──────────────────────────────────────────────────────────────────────────────
# 3. Run the gateway
# ──────────────────────────────────────────────────────────────────────────────
docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

docker run -d \
  --name "$CONTAINER_NAME" \
  -p "$TEAMS_PORT:$TEAMS_PORT" \
  -p "$ATLASSIAN_PORT:$ATLASSIAN_PORT" \
  -p "$ADMIN_PORT:15000" \
  -p "$STATS_PORT:15020" \
  -p "$READINESS_PORT:15021" \
  -e ADMIN_ADDR=0.0.0.0:15000 \
  -v "$CONFIG_FILE:/etc/agentgateway/config.yaml:ro" \
  "$IMAGE" \
  -f /etc/agentgateway/config.yaml \
  >/dev/null

# Wait for readiness
for _ in $(seq 1 20); do
  if curl -sf "http://localhost:$READINESS_PORT/healthz/ready" >/dev/null 2>&1 \
     || docker logs "$CONTAINER_NAME" 2>&1 | grep -q "marking server ready"; then
    break
  fi
  sleep 0.5
done

# ──────────────────────────────────────────────────────────────────────────────
# 4. Print connection info
# ──────────────────────────────────────────────────────────────────────────────
cat <<EOF

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✓ kindred-mcp-gateway running locally as container '$CONTAINER_NAME'
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Admin UI         http://localhost:$ADMIN_PORT/ui
Metrics          http://localhost:$STATS_PORT/metrics
Readiness probe  http://localhost:$READINESS_PORT/healthz/ready

MCP endpoints (use these as URL in your LibreChat librechat.yaml):

  Teams           http://localhost:$TEAMS_PORT/teams
                  Headers required:
                    Authorization: Bearer <Microsoft Graph access token>
                    X-User-Email:  <your kindredgroup.com email>

                  ⚠ Upstream ms365-mcp-dev.kindredgroup.com is internal-only;
                    you must be on the corp VPN for tool calls to actually work.

  Atlassian/Jira      http://localhost:$ATLASSIAN_PORT/jira
                      OAuth scope: read:jira-work write:jira-work read:jira-user read:me offline_access

  Atlassian/Conflu.   http://localhost:$ATLASSIAN_PORT/confluence
                      OAuth scope: read:confluence-content.all write:confluence-content
                                   read:confluence-space.summary search:confluence
                                   read:me offline_access

Subcommands:
  $0 logs     # follow logs
  $0 shell    # open a debugging shell
  $0 stop     # stop and remove the container

EOF
