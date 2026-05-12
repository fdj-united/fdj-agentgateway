#!/usr/bin/env bash
# Run the kindred-mcp-gateway locally as a NATIVE Rust process (no Docker).
# Uses the host network stack — VPN DNS works automatically, no container DNS quirks.
#
#   - Builds agentgateway from your local fork at /Users/romy/Documents/agentgateway
#     (cached — only rebuilds when source changes).
#   - Renders the helm chart against a local-only values file.
#   - Extracts and validates the agentgateway config.
#   - Runs the binary in the foreground or background.
#
# Usage:
#   ./scripts/run-local-native.sh           # start in foreground (Ctrl+C to stop)
#   ./scripts/run-local-native.sh -d        # start in background
#   ./scripts/run-local-native.sh stop      # stop a backgrounded process
#   ./scripts/run-local-native.sh logs      # tail logs (background mode only)
#
# Prereqs: cargo, helm, ruby, python3

set -euo pipefail

# ──────────────────────────────────────────────────────────────────────────────
# Config
# ──────────────────────────────────────────────────────────────────────────────
AGW_REPO="${AGW_REPO:-/Users/romy/Documents/agentgateway}"
BINARY="$AGW_REPO/target/release/agentgateway"

TEAMS_PORT=8081
ATLASSIAN_PORT=8082
ADMIN_PORT=15000

CHART_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/helm"

WORK_DIR="${TMPDIR:-/tmp}/kindred-mcp-gateway-local-native"
VALUES_FILE="$WORK_DIR/local-values.yaml"
RENDERED_FILE="$WORK_DIR/rendered.yaml"
CONFIG_FILE="$WORK_DIR/config.yaml"
PID_FILE="$WORK_DIR/agentgateway.pid"
LOG_FILE="$WORK_DIR/agentgateway.log"

# ──────────────────────────────────────────────────────────────────────────────
# Subcommands
# ──────────────────────────────────────────────────────────────────────────────
case "${1:-start}" in
  stop)
    if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
      kill "$(cat "$PID_FILE")"
      sleep 0.3
      kill -9 "$(cat "$PID_FILE")" 2>/dev/null || true
      rm -f "$PID_FILE"
      echo "Stopped agentgateway"
    else
      echo "agentgateway not running"
    fi
    exit 0
    ;;
  logs)
    [[ -f "$LOG_FILE" ]] || { echo "no log file (run started in foreground or not yet)"; exit 1; }
    tail -f "$LOG_FILE"
    exit 0
    ;;
  -d|--detach|background)
    BACKGROUND=1
    ;;
  start|"")
    BACKGROUND=0
    ;;
  *)
    echo "Usage: $0 {start|stop|logs|-d}"
    exit 1
    ;;
esac

mkdir -p "$WORK_DIR"

# ──────────────────────────────────────────────────────────────────────────────
# 1. Refuse to start if a previous instance is already running
# ──────────────────────────────────────────────────────────────────────────────
if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
  echo "agentgateway is already running (pid $(cat "$PID_FILE")). Run '$0 stop' first."
  exit 1
fi

# Free up any process accidentally holding our ports (e.g. orphan from previous run)
for port in "$TEAMS_PORT" "$ATLASSIAN_PORT" "$ADMIN_PORT"; do
  pid="$(lsof -ti tcp:"$port" -sTCP:LISTEN 2>/dev/null || true)"
  if [[ -n "$pid" ]]; then
    echo "⚠ port $port is in use by pid $pid — leaving it alone, agentgateway will fail to bind."
    echo "   kill it manually if needed: kill $pid"
  fi
done

# ──────────────────────────────────────────────────────────────────────────────
# 2. Build the binary if missing or stale
# ──────────────────────────────────────────────────────────────────────────────
if [[ ! -d "$AGW_REPO" ]]; then
  echo "agentgateway repo not found at $AGW_REPO — set AGW_REPO env var" >&2
  exit 1
fi

# Stale check: rebuild if any .rs source is newer than the binary
needs_build=0
if [[ ! -x "$BINARY" ]]; then
  needs_build=1
elif [[ -n "$(find "$AGW_REPO/crates" -name '*.rs' -newer "$BINARY" -print -quit 2>/dev/null)" ]]; then
  needs_build=1
fi

if (( needs_build )); then
  echo "Building agentgateway (release) — this can take a few minutes the first time…"
  ( cd "$AGW_REPO" && cargo build --release --bin agentgateway )
else
  echo "✓ Using cached binary at $BINARY"
fi

# ──────────────────────────────────────────────────────────────────────────────
# 3. Build a local-friendly values file (same shape as run-local.sh)
# ──────────────────────────────────────────────────────────────────────────────
cat > "$VALUES_FILE" <<EOF
image:
  registry: ghcr.io/fdj-united
  repository: agentgateway
  tag: "v0.0.7"

ingress:
  enabled: false
admin:
  enabled: false

cors:
  allowOrigins: ["*"]
  allowHeaders: ["mcp-protocol-version", "content-type", "cache-control", "Accept", "Authorization", "X-User-Email"]

frontendPolicies:
  accessLog:
    user: 'request.headers["X-User-Email"]'

listeners:
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
            value: "<br><br><i>— Sent via KAIT (LOCAL NATIVE)</i>"
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

  - name: atlassian
    port: $ATLASSIAN_PORT
    backends:
      - name: jira
        routePath: /jira
        mcp:
          host: https://mcp.atlassian.com/v1/mcp
        # mcpAuthentication intentionally omitted in local dev — Zscaler intercepts the
        # JWKS fetch and agentgateway can't trust the inserted cert. OAuth metadata
        # generation is therefore disabled locally; LibreChat must use a static Bearer
        # token via the `headers` block instead of the OAuth flow.
        confirmation:
          ttlSeconds: 120
          rules:
            - 'mcp.tool.name in ["createJiraIssue", "editJiraIssue", "transitionJiraIssue", "addCommentToJiraIssue"]'
        authorization:
          - 'mcp.tool.name in ["atlassianUserInfo", "getAccessibleAtlassianResources", "getJiraIssue", "editJiraIssue", "createJiraIssue", "getTransitionsForJiraIssue", "transitionJiraIssue", "lookupJiraAccountId", "searchJiraIssuesUsingJql", "addCommentToJiraIssue", "getJiraIssueRemoteIssueLinks", "getVisibleJiraProjects", "getJiraProjectIssueTypesMetadata"]'

      - name: confluence
        routePath: /confluence
        mcp:
          host: https://mcp.atlassian.com/v1/mcp
        # mcpAuthentication omitted — see comment on the jira backend above.
        confirmation:
          ttlSeconds: 120
          rules:
            - 'mcp.tool.name in ["createConfluencePage", "updateConfluencePage", "createConfluenceFooterComment", "createConfluenceInlineComment"]'
        authorization:
          - 'mcp.tool.name in ["atlassianUserInfo", "getAccessibleAtlassianResources", "createConfluenceFooterComment", "createConfluenceInlineComment", "createConfluencePage", "getConfluencePage", "getConfluencePageDescendants", "getConfluencePageFooterComments", "getConfluencePageInlineComments", "getConfluenceSpaces", "getPagesInConfluenceSpace", "searchConfluenceUsingCql", "updateConfluencePage"]'
EOF

# ──────────────────────────────────────────────────────────────────────────────
# 4. Render the chart and extract the agentgateway config
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

ruby -ryaml -e 'YAML.load_file(ARGV[0])' "$CONFIG_FILE" >/dev/null

echo "✓ Config rendered to $CONFIG_FILE"

# ──────────────────────────────────────────────────────────────────────────────
# 5. Print connection info
# ──────────────────────────────────────────────────────────────────────────────
banner() {
cat <<EOF

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✓ kindred-mcp-gateway running NATIVELY (no Docker — uses host network)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Admin UI         http://localhost:$ADMIN_PORT/ui

MCP endpoints (use these in your local librechat.yaml):

  Teams              http://localhost:$TEAMS_PORT/teams
                     Headers: Authorization: Bearer <Graph token>, X-User-Email
                     (uses your VPN-pushed DNS — ms365-mcp-dev resolves correctly)

  Atlassian/Jira     http://localhost:$ATLASSIAN_PORT/jira
                     OAuth — set 'oauth.scope' in librechat.yaml, no headers

  Atlassian/Conflu.  http://localhost:$ATLASSIAN_PORT/confluence
                     OAuth — set 'oauth.scope' in librechat.yaml, no headers

EOF
}

# ──────────────────────────────────────────────────────────────────────────────
# 6. Run the gateway
# ──────────────────────────────────────────────────────────────────────────────
ADMIN_ADDR="0.0.0.0:$ADMIN_PORT"
export ADMIN_ADDR

if (( BACKGROUND )); then
  : > "$LOG_FILE"
  nohup "$BINARY" -f "$CONFIG_FILE" > "$LOG_FILE" 2>&1 &
  echo $! > "$PID_FILE"
  sleep 0.5
  if ! kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "agentgateway exited immediately. Logs:"
    tail -50 "$LOG_FILE"
    exit 1
  fi
  banner
  echo "Background pid: $(cat "$PID_FILE")"
  echo "Logs:           tail -f $LOG_FILE   (or '$0 logs')"
  echo "Stop:           $0 stop"
else
  banner
  echo "Running in foreground — Ctrl+C to stop. (Use '$0 -d' to background.)"
  exec "$BINARY" -f "$CONFIG_FILE"
fi
