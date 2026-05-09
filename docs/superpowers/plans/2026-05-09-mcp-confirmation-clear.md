# MCP Confirmation Pending-Approval Clear Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an explicit "clear pending approval" signal from LibreChat to agentgateway so a user-decline reliably evicts the gateway's pending entry — fixing the silent-bypass bug where retrying a declined call within 120s skips the modal.

**Architecture:** Sentinel-arg-in-`tools/call`. The LibreChat backend, after `awaitConfirmationDecision` resolves with cancel/timeout, fires (don't await) a `tools/call` with the original args plus `__mcp_clear_pending__: true`. The gateway intercepts the sentinel near the top of its `tools/call` handler — strips the sentinel, re-derives the same `(tool, hash(stripped_args))` key Phase 1 used, removes the matching entry, returns `{cleared: true|false}`. **Never forwards upstream.** Bypasses rate-limit, auth-filter, arg-rewrite, confirmation. Best-effort: clear failure → log + continue + TTL fallback.

**Tech Stack:** Rust (agentgateway, cargo workspace) + JavaScript (LibreChat, jest tests). Two repos, single coordinated feature.

**Spec:** [docs/superpowers/specs/2026-05-09-mcp-confirmation-clear-design.md](../specs/2026-05-09-mcp-confirmation-clear-design.md). Read §1 (problem), §3 (wire format + design picks), §4 (lifecycle), §6 (edge cases), §8 (locked decisions) before starting.

---

## Cross-repo coordination

Ship in this order, separate PRs:

1. **agentgateway PR** (Tasks 1-3) lands first. Gateway recognizes the sentinel; the change is a no-op for any client that doesn't yet send it. Backwards-compatible.
2. **Fdj-LibreChat PR** (Task 4) lands after. LibreChat starts emitting clears on every cancel/timeout. The agentgateway side is already deployed and ready to honor them.

Both PRs depend on the spec at [docs/superpowers/specs/2026-05-09-mcp-confirmation-clear-design.md](../specs/2026-05-09-mcp-confirmation-clear-design.md) (in the agentgateway repo). Cross-repo reviewers should reference it.

---

## File structure

| Repo | File | Change | Why |
|---|---|---|---|
| agentgateway | `crates/agentgateway/src/mcp/mod.rs` | NEW: `pub const MCP_CLEAR_PENDING_SENTINEL: &str = "__mcp_clear_pending__";` | Single source of truth for the sentinel name; referenced by both detection + schema-collision check. |
| agentgateway | `crates/agentgateway/src/mcp/handler.rs` | In `Relay::merge_tools` (already touched by enrichment work — same place as `apply_to_schema`): scan each tool's `input_schema.properties` for the sentinel; if found, return Err. | Refuse-to-serve any tool whose schema declares the sentinel as a real property (defense against accidental collision). |
| agentgateway | `crates/agentgateway/src/mcp/session.rs` | In the `ClientRequest::CallToolRequest` arm (around line 393), immediately after `let call_arguments = ...` (line 397), check the sentinel. If present: strip it, compute the same key Phase 1 uses (`enrichment.strip` + `hash_args`), `pending_approvals.remove(key)`, return a `CallToolResult::success` with text `{"cleared": true\|false}`, short-circuit. | The sentinel-detection short-circuit. Must run BEFORE auth filter, rate limit, confirmation, arg-rewrite. |
| agentgateway | `crates/agentgateway/src/mcp/mcp_tests.rs` | New tests covering: clear-removes-pending, clear-with-no-matching-entry, clear-not-forwarded-upstream, clear-bypasses-rate-limit, schema-collision-refuses-to-serve. | Lock the contract. |
| Fdj-LibreChat | `api/server/services/MCP.js` | In the `else` branch around lines 752-758 (handles cancel + timeout): before the `buildCanceledToolResult(provider, reason)` call at line 757, fire-and-forget `mcpManager.callTool({ ...callToolArgs, toolArguments: { ...callToolArgs.toolArguments, __mcp_clear_pending__: true } })` with `.catch(...)` for logging. | Issue the clear on every cancel/timeout. |
| Fdj-LibreChat | `api/server/services/__tests__/MCPConfirmation.spec.js` | Integration tests: cancel-issues-clear, cancel-clear-failure-doesnt-block-stub-return. | Lock the LibreChat side of the contract. |

**Out of scope** (per spec §7): retry-with-backoff on clear failure, bulk clear, clearing-by-confirmationId, dedicated audit fields, server-side push notification.

---

## Test strategy

- **Gateway unit tests** in `mcp_tests.rs` cover the sentinel-detection short-circuit and the schema-collision refusal. Use existing `setup_proxy_policies` helper to drive a real relay against the mock streamable-HTTP server. The mock's echo tool acts as a witness for "did upstream get called?" (it shouldn't, for clears).
- **LibreChat integration tests** in `MCPConfirmation.spec.js` cover the cancel-issues-clear behavior and the failure-doesnt-block invariant. Mock `mcpManager.callTool` to assert the second call shape.
- **Manual end-to-end** (Task 5) reproduces the original bug-report sequence and verifies it no longer triggers.

---

## Conventions

- **agentgateway:** match existing commit style (lowercase, terse). Run `cargo check -p agentgateway` after every code change before committing. Run `cargo test -p agentgateway --lib mcp` to confirm no regression. Co-Authored-By trailer: `Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>`.
- **Fdj-LibreChat:** match existing commit style. Run `npx jest --testPathPatterns="MCPConfirmation" --no-coverage` from `client/` (or wherever jest runs in this fork — earlier work used `client/`) to confirm no regression. Same Co-Authored-By trailer.
- Do NOT skip git hooks. Do NOT amend; create new commits.
- Touch ONLY the files listed in each task. The pre-existing dirty `Dockerfile`, `package.json`, `detectOAuth.ts`, untracked `librechat-mcp-confirmation.patch`, and `local.config.yaml` should remain UNTOUCHED across all tasks.

---

## Task 1: agentgateway — sentinel constant + schema-collision check

**Files:**
- Modify: `crates/agentgateway/src/mcp/mod.rs` — add `MCP_CLEAR_PENDING_SENTINEL` constant.
- Modify: `crates/agentgateway/src/mcp/handler.rs` — extend the existing enrichment loop in `merge_tools` to also scan for the sentinel.
- Modify: `crates/agentgateway/src/mcp/mcp_tests.rs` — add a test for the schema-collision refusal.

**Context:** This task is scaffolding. The constant is referenced by both detection (Task 2) and the schema-collision check (this task). The schema-collision check piggybacks on the existing enrichment-conflict logic in `merge_tools` — same location, same `Arc::make_mut` access pattern, same `ClientError::new(anyhow!(...))` failure mode.

The existing enrichment integration in `merge_tools` is around lines 195-220 (per the agentgateway feat/two-phase-auth branch). Look for:
```rust
if !enrichment.is_empty() {
    let schema = Arc::make_mut(&mut t.input_schema);
    enrichment
        .apply_to_schema(t.name.as_ref(), schema)
        .map_err(|e| ClientError::new(e.context("mcpToolEnrichment")))?;
}
```

Your check goes RIGHT BEFORE this (so the schema is still the original Arc — no need to `make_mut` just to read).

- [ ] **Step 1: Write the failing test** in `mcp_tests.rs`

Append inside whatever describes-merge_tools test mod is at the bottom of the file. If no such mod exists, add a new `#[tokio::test]` near the existing `enrichment_injects_field_into_tools_list_response` test (~line 528+ in the post-feat/two-phase-auth state):

```rust
#[tokio::test]
async fn merge_tools_refuses_to_serve_when_tool_schema_collides_with_clear_sentinel() {
    use crate::mcp::MCP_CLEAR_PENDING_SENTINEL;
    let mut server = mock_server();
    server.add_tool(
        "evil-tool",
        json!({
            "type": "object",
            "properties": {
                MCP_CLEAR_PENDING_SENTINEL: { "type": "boolean" }
            }
        }),
    );
    let upstream = server.spawn().await;

    let client = setup_proxy_policies(upstream, vec![]).await;

    let err = client
        .list_tools(None)
        .await
        .expect_err("expected merge_tools to refuse a colliding schema");

    let msg = format!("{err:?}");
    assert!(
        msg.contains(MCP_CLEAR_PENDING_SENTINEL),
        "error must name the sentinel — got: {msg}"
    );
    assert!(
        msg.to_lowercase().contains("evil-tool"),
        "error must name the offending tool — got: {msg}"
    );
}
```

(Adapt `mock_server`, `setup_proxy_policies`, and the `add_tool` helper signatures to match what's already in `mcp_tests.rs` — the existing `enrichment_injects_field_into_tools_list_response` test is the harness pattern.)

- [ ] **Step 2: Run to verify the test fails**

```bash
cd /Users/romuald/Projects/FDJ-Projects/fdj-agentgateway
cargo test -p agentgateway --lib mcp::tests::merge_tools_refuses_to_serve_when_tool_schema_collides_with_clear_sentinel 2>&1 | tail -20
```

Expected: FAIL — either compile error (`MCP_CLEAR_PENDING_SENTINEL` doesn't exist) or runtime error (collision check not in place; `list_tools` returns Ok unexpectedly).

- [ ] **Step 3: Add the constant**

In `crates/agentgateway/src/mcp/mod.rs`, find the existing `pub use rbac::{...}` re-exports and ADD a new public constant near the top of the file (or near the existing exports):

```rust
/// Sentinel argument that, when present and `true` on a `tools/call` request,
/// signals to the gateway "clear the pending-approval entry for this
/// (tool, args) — do NOT actually call upstream." Used by LibreChat to evict
/// stale pending entries when the user declines a confirmation modal so that
/// a subsequent identical call within the gateway-side TTL doesn't bypass
/// confirmation.
///
/// See [docs/superpowers/specs/2026-05-09-mcp-confirmation-clear-design.md](../../../docs/superpowers/specs/2026-05-09-mcp-confirmation-clear-design.md).
pub const MCP_CLEAR_PENDING_SENTINEL: &str = "__mcp_clear_pending__";
```

- [ ] **Step 4: Add the schema-collision check**

In `crates/agentgateway/src/mcp/handler.rs`, find `merge_tools`. Before the existing `if !enrichment.is_empty() { ... }` block (the enrichment integration site), add a sentinel-collision check:

```rust
            // Refuse-to-serve any tool whose schema declares the clear sentinel
            // as a real property — would collide with the gateway's clear hook.
            // (See spec §6.1.)
            if let Some(serde_json::Value::Object(props)) =
                t.input_schema.get("properties")
            {
                if props.contains_key(MCP_CLEAR_PENDING_SENTINEL) {
                    return Err(ClientError::new(anyhow::anyhow!(
                        "tool '{}' declares the reserved property '{}' — \
                         this name is reserved by the gateway for the \
                         pending-approval clear sentinel; rename the property \
                         to avoid the collision",
                        t.name,
                        MCP_CLEAR_PENDING_SENTINEL
                    )));
                }
            }
```

Add `use crate::mcp::MCP_CLEAR_PENDING_SENTINEL;` near the top of the file if needed.

- [ ] **Step 5: Verify the new test passes + no regression**

```bash
cargo test -p agentgateway --lib mcp::tests::merge_tools_refuses_to_serve_when_tool_schema_collides_with_clear_sentinel 2>&1 | tail -10
cargo test -p agentgateway --lib mcp 2>&1 | tail -10
```

Expected: new test passes. Full mcp suite remains green (was 134 — should now be 135).

- [ ] **Step 6: Commit**

```bash
git add crates/agentgateway/src/mcp/mod.rs crates/agentgateway/src/mcp/handler.rs crates/agentgateway/src/mcp/mcp_tests.rs
git commit -m "$(cat <<'EOF'
mcp: add MCP_CLEAR_PENDING_SENTINEL constant + schema-collision refusal

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: agentgateway — sentinel-detection short-circuit in session.rs

**Files:**
- Modify: `crates/agentgateway/src/mcp/session.rs` — add sentinel-detection block in the `ClientRequest::CallToolRequest` arm.
- Modify: `crates/agentgateway/src/mcp/mcp_tests.rs` — add 4 tests covering the clear behavior.

**Context:** The `ClientRequest::CallToolRequest` arm starts at line 393 of `session.rs` (per current feat/two-phase-auth state). Line 397 extracts `let call_arguments = ctr.params.arguments.clone();`. Your sentinel detection goes IMMEDIATELY AFTER line 397, BEFORE everything else (auth filter, rate limit, confirmation block at line 453+).

Use the same `enrichment.strip` + `hash_args` pattern that the confirmation block uses (lines 466-470) for the lookup-key derivation, so Phase-1 and clear hash identical args.

The pending_approvals lookup uses the same key format Phase 1 uses: `format!("{}|{:016x}", name, hash_args(for_hash.as_ref()))`. The `name` here is the SHORT tool name (post-multiplexing rename) — same as Phase 1.

- [ ] **Step 1: Write the failing tests** in `mcp_tests.rs`

Append the following 4 tests near the existing confirmation tests (alongside `enrichment_field_stripped_before_upstream_and_survives_phase2_rehash` from the queue work):

```rust
#[tokio::test]
async fn clear_removes_pending_approval_so_subsequent_call_re_triggers_phase_1() {
    // Setup: tool with mcpConfirmation policy.
    let server = mock_server_with_confirmable_tool().await;
    let upstream = server.spawn().await;
    let client = setup_proxy_policies(
        upstream,
        vec![BackendPolicy::McpConfirmation(/* CEL matches the tool */)],
    )
    .await;

    // Phase 1: original call returns a confirmation envelope.
    let phase1 = client
        .call_tool("dangerous-tool", json!({ "id": "x123" }))
        .await
        .unwrap();
    assert!(extract_envelope(&phase1).contains("confirmationRequired"));

    // Clear: send a tools/call with the sentinel.
    let cleared = client
        .call_tool(
            "dangerous-tool",
            json!({ "id": "x123", "__mcp_clear_pending__": true }),
        )
        .await
        .unwrap();
    let cleared_text = extract_text(&cleared);
    assert!(
        cleared_text.contains("\"cleared\":true") || cleared_text.contains("\"cleared\": true"),
        "expected cleared:true got {cleared_text}"
    );

    // Subsequent identical call: pending entry was cleared, so Phase 1 fires
    // again with a fresh envelope (NOT a Phase-2 upstream forward).
    let phase1_again = client
        .call_tool("dangerous-tool", json!({ "id": "x123" }))
        .await
        .unwrap();
    assert!(
        extract_envelope(&phase1_again).contains("confirmationRequired"),
        "after clear, an identical call should re-trigger Phase 1, not bypass"
    );
}

#[tokio::test]
async fn clear_with_no_matching_entry_returns_cleared_false() {
    let server = mock_server_with_confirmable_tool().await;
    let upstream = server.spawn().await;
    let client = setup_proxy_policies(
        upstream,
        vec![BackendPolicy::McpConfirmation(/* CEL matches the tool */)],
    )
    .await;

    // No prior Phase 1; clear has nothing to remove.
    let cleared = client
        .call_tool(
            "dangerous-tool",
            json!({ "id": "x123", "__mcp_clear_pending__": true }),
        )
        .await
        .unwrap();
    let cleared_text = extract_text(&cleared);
    assert!(
        cleared_text.contains("\"cleared\":false") || cleared_text.contains("\"cleared\": false"),
        "expected cleared:false got {cleared_text}"
    );
}

#[tokio::test]
async fn clear_is_never_forwarded_upstream() {
    // The mock backend's echo tool reflects its received args back as the
    // response. If a clear were forwarded, the response would echo args
    // including the sentinel. Instead, we expect a {cleared: ...} JSON.
    let upstream_calls = std::sync::Arc::new(std::sync::Mutex::new(0u32));
    let mut server = mock_server();
    server.add_tool_with_handler("echo", {
        let counter = upstream_calls.clone();
        move |_args| {
            *counter.lock().unwrap() += 1;
            json!({ "did_reach_upstream": true })
        }
    });
    let upstream = server.spawn().await;
    let client = setup_proxy_policies(
        upstream,
        vec![BackendPolicy::McpConfirmation(/* CEL matches "echo" */)],
    )
    .await;

    // Clear (no prior Phase 1 needed for this assertion).
    let _ = client
        .call_tool(
            "echo",
            json!({ "x": "y", "__mcp_clear_pending__": true }),
        )
        .await
        .unwrap();

    assert_eq!(
        *upstream_calls.lock().unwrap(),
        0,
        "clear must not reach the upstream MCP server"
    );
}

#[tokio::test]
async fn clear_bypasses_rate_limit_so_user_can_decline_freely() {
    // Setup: tool with mcpConfirmation + a tight mcpRateLimit (e.g. 2 calls
    // per minute). Issue 2 Phase-1 calls (consumes the rate-limit quota),
    // then 5 clears in rapid succession. All 5 clears must succeed.
    let server = mock_server_with_confirmable_tool().await;
    let upstream = server.spawn().await;
    let client = setup_proxy_policies(
        upstream,
        vec![
            BackendPolicy::McpConfirmation(/* CEL matches the tool */),
            BackendPolicy::McpRateLimit(/* maxCalls: 2, windowSeconds: 60 */),
        ],
    )
    .await;

    // Burn the rate-limit quota with 2 Phase-1 calls.
    let _ = client.call_tool("dangerous-tool", json!({ "id": "1" })).await.unwrap();
    let _ = client.call_tool("dangerous-tool", json!({ "id": "2" })).await.unwrap();

    // 5 clears in a row must all return success without rate-limit rejection.
    for i in 0..5 {
        let cleared = client
            .call_tool(
                "dangerous-tool",
                json!({ "id": format!("{i}"), "__mcp_clear_pending__": true }),
            )
            .await
            .unwrap_or_else(|e| panic!("clear {i} was rejected: {e:?}"));
        let cleared_text = extract_text(&cleared);
        assert!(
            cleared_text.contains("\"cleared\""),
            "clear {i} did not return a cleared response: {cleared_text}"
        );
    }
}
```

(All 4 tests use helpers like `mock_server_with_confirmable_tool`, `extract_envelope`, `extract_text`, `BackendPolicy::McpConfirmation(...)`. Adapt to whatever helpers are already in `mcp_tests.rs` — the existing confirmation tests from spec [2026-05-05](../specs/2026-05-05-tool-schema-injection-design.md) work and Task 7 of the enrichment plan already established the harness pattern. If a helper doesn't exist, build a minimal version that mirrors what the enrichment integration test does. If you need to invent CEL rules, copy from `local.config.yaml` — `"mcp.tool.name == \"dangerous-tool\""` is the basic shape.)

- [ ] **Step 2: Run to verify the tests fail**

```bash
cargo test -p agentgateway --lib mcp 2>&1 | grep -E "^test|^FAIL|test result" | tail -15
```

Expected: 4 new tests fail (sentinel-detection not implemented yet). Existing tests still pass.

- [ ] **Step 3: Implement the sentinel-detection short-circuit**

In `crates/agentgateway/src/mcp/session.rs`, find the `ClientRequest::CallToolRequest(ctr) => {` arm at line 393. Find `let call_arguments = ctr.params.arguments.clone();` at line 397. Insert the following block IMMEDIATELY AFTER that line, BEFORE any other logic in the arm:

```rust
                        // ── Pending-approval clear (sentinel short-circuit) ──
                        // If the LLM (i.e. LibreChat) sent the clear sentinel,
                        // strip the sentinel from a clone of the args, re-derive
                        // the same (tool, hash(stripped_args)) key Phase 1 used,
                        // remove the matching pending entry if present, and return
                        // a {cleared: ...} result. NEVER forwards upstream and
                        // bypasses ALL other policy checks (auth, rate-limit,
                        // arg-rewrite, confirmation). See spec §3 + §6.
                        if let Some(args) = call_arguments.as_ref() {
                            if matches!(
                                args.get(crate::mcp::MCP_CLEAR_PENDING_SENTINEL),
                                Some(serde_json::Value::Bool(true))
                            ) {
                                // Compute the same lookup key Phase 1 uses.
                                let cleared = if self.is_stateful {
                                    let mut for_hash = call_arguments.clone();
                                    if let Some(map) = for_hash.as_mut() {
                                        map.remove(crate::mcp::MCP_CLEAR_PENDING_SENTINEL);
                                    }
                                    self.relay.enrichment.strip(tool, &mut for_hash);
                                    let key = format!(
                                        "{}|{:016x}",
                                        name,
                                        hash_args(for_hash.as_ref())
                                    );
                                    let mut approvals = self.pending_approvals.lock().await;
                                    approvals.remove(&key).is_some()
                                } else {
                                    // Stateless session has no pending_approvals at
                                    // all — clear is trivially a no-op.
                                    false
                                };
                                let body = if cleared {
                                    "{\"cleared\":true}"
                                } else {
                                    "{\"cleared\":false}"
                                };
                                let msg = ServerJsonRpcMessage::response(
                                    ServerResult::CallToolResult(
                                        CallToolResult::success(vec![Content::text(body)]),
                                    ),
                                    r.id.clone(),
                                );
                                use futures_util::stream;
                                return crate::mcp::handler::messages_to_response(
                                    r.id,
                                    stream::once(async move { Ok(msg) }),
                                    None,
                                );
                            }
                        }
                        // ── End pending-approval clear ──
```

(Note: `tool`, `name`, and `r` are already in scope at this point in the existing handler — see how the confirmation block uses them at line 460. If they're NOT yet bound at line 397, move them up so the sentinel block can use them. Read the surrounding code.)

- [ ] **Step 4: Verify all tests pass**

```bash
cargo test -p agentgateway --lib mcp 2>&1 | tail -10
```

Expected: full mcp suite green. Total: 138 (134 + 1 schema-collision from Task 1 + 4 from this task).

- [ ] **Step 5: Commit**

```bash
git add crates/agentgateway/src/mcp/session.rs crates/agentgateway/src/mcp/mcp_tests.rs
git commit -m "$(cat <<'EOF'
mcp: sentinel-detection short-circuit clears pending approval

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Fdj-LibreChat — fire-and-forget clear on cancel/timeout

**Files:**
- Modify: `Fdj-LibreChat/api/server/services/MCP.js` — in the `awaitConfirmationDecision` cancel/timeout branch (around lines 752-758), issue the clear before constructing the canceled stub.
- Modify: `Fdj-LibreChat/api/server/services/__tests__/MCPConfirmation.spec.js` — add 2 integration tests.

**Context:** This task is in a different repo. Switch repos before starting:

```bash
cd /Users/romuald/Projects/FDJ-Projects/Fdj-LibreChat
git status --short
```

Confirm you're on the branch the user wants this to land on. If unsure, STOP and ask the controller. (As of the spec writing, the queue-model branch `feat/mcp-confirmation-queue` is open with its own PR pending — this clear feature should likely go on a SEPARATE branch like `feat/mcp-confirmation-clear` cut from `test/librechat-0.8.3` or main. Do NOT just commit to whatever branch is currently checked out without verifying.)

The existing cancel/timeout branch in `MCP.js` (lines 752-758) looks like:

```javascript
        } else {
          const reason =
            decision === 'timeout'
              ? 'User did not confirm in time.'
              : 'User declined.';
          result = buildCanceledToolResult(provider, reason);
        }
```

Your change inserts the clear BEFORE the `buildCanceledToolResult` call. Fire-and-forget (don't await — the canceled stub return must not block on the clear's response).

- [ ] **Step 1: Verify the working tree state**

```bash
cd /Users/romuald/Projects/FDJ-Projects/Fdj-LibreChat
git status --short
git branch --show-current
git log --oneline -3
```

If the current branch is NOT a fresh clear-feature branch, STOP and ask the controller. Likely action: `git checkout -b feat/mcp-confirmation-clear` from a clean base (probably `test/librechat-0.8.3` or wherever the queue branch was cut from, depending on whether the queue work has merged).

- [ ] **Step 2: Write the failing tests** in `MCPConfirmation.spec.js`

Append to the existing describe block (or add a new one). The test framework + harness already exists from the original two-phase confirmation work — read what's at the top of the file to see the imports.

```javascript
describe('Pending-approval clear on cancel/timeout', () => {
  it('issues a clear via mcpManager.callTool with the sentinel after a cancel', async () => {
    // Setup: trigger a confirmation flow that the user cancels.
    const calls = [];
    const mockMcpManager = {
      callTool: jest.fn(async (args) => {
        calls.push(args);
        // First call returns a confirmation envelope.
        if (calls.length === 1) {
          return [
            { type: 'text', text: JSON.stringify({ confirmationRequired: true, preview: 'x', expiresInSeconds: 120 }) },
          ];
        }
        // Second call (the clear) returns the cleared response.
        return [
          { type: 'text', text: JSON.stringify({ cleared: true }) },
        ];
      }),
    };
    // ... wire up the harness so awaitConfirmationDecision resolves with cancel ...
    // (Reuse the existing test setup from MCPConfirmation.spec.js — search for
    //  how the existing "cancel" test triggers it.)

    await invokeToolWithCancel(mockMcpManager, /* args */);

    // The second call MUST be the clear.
    expect(calls.length).toBe(2);
    expect(calls[1].toolArguments).toMatchObject({ __mcp_clear_pending__: true });
    // And it must preserve the original args (so the gateway can re-derive the key).
    expect(calls[1].toolArguments).toMatchObject({ /* original args */ });
  });

  it('returns the canceled stub even if the clear call fails', async () => {
    const mockMcpManager = {
      callTool: jest.fn()
        .mockResolvedValueOnce([
          { type: 'text', text: JSON.stringify({ confirmationRequired: true, preview: 'x', expiresInSeconds: 120 }) },
        ])
        .mockRejectedValueOnce(new Error('network down')),
    };

    const result = await invokeToolWithCancel(mockMcpManager, /* args */);

    // The canceled stub is returned regardless of the clear's failure.
    const text = extractText(result);
    expect(text).toMatch(/canceled.*true/);
  });
});
```

(Adapt `invokeToolWithCancel`, `extractText`, and the mock-mcpManager wiring to match what the existing tests in `MCPConfirmation.spec.js` use. The existing 6 tests there already exercise the `_call` wrapper end-to-end — your new tests reuse the same harness with different `decision` outcomes from `awaitConfirmationDecision`.)

- [ ] **Step 3: Run to verify the tests fail**

```bash
cd /Users/romuald/Projects/FDJ-Projects/Fdj-LibreChat
npx jest --testPathPatterns="MCPConfirmation" --no-coverage 2>&1 | tail -20
```

Expected: 2 new tests fail (clear not yet issued).

- [ ] **Step 4: Add the fire-and-forget clear**

In `Fdj-LibreChat/api/server/services/MCP.js`, find the `else` branch at lines 752-758. Currently:

```javascript
        } else {
          const reason =
            decision === 'timeout'
              ? 'User did not confirm in time.'
              : 'User declined.';
          result = buildCanceledToolResult(provider, reason);
        }
```

Replace with:

```javascript
        } else {
          const reason =
            decision === 'timeout'
              ? 'User did not confirm in time.'
              : 'User declined.';

          // Fire-and-forget clear of the gateway-side pending entry. Without
          // this, the gateway's pending_approvals map keeps the entry until
          // its 120s TTL — and a retry of the same (tool, args) within that
          // window silently bypasses the modal.
          //
          // Best-effort: if the clear call fails, we still return the
          // canceled stub. The gateway's TTL is the fallback.
          //
          // See agentgateway/docs/superpowers/specs/2026-05-09-mcp-confirmation-clear-design.md
          const clearArgs = {
            ...callToolArgs,
            toolArguments: {
              ...callToolArgs.toolArguments,
              __mcp_clear_pending__: true,
            },
          };
          void mcpManager.callTool(clearArgs).catch((err) => {
            logger.warn(
              `[MCP][${serverName}][${toolName}][User: ${userId}] Failed to clear gateway-side pending approval (best-effort; TTL is fallback): ${err.message}`,
            );
          });

          result = buildCanceledToolResult(provider, reason);
        }
```

Verify `logger` is in scope at this site — it should be, since the existing `logger.info(...)` calls in the wrapper use it.

- [ ] **Step 5: Verify all tests pass**

```bash
npx jest --testPathPatterns="MCPConfirmation" --no-coverage 2>&1 | tail -15
```

Expected: full file green (existing 6 tests + your 2 new tests = 8 pass).

- [ ] **Step 6: Commit**

```bash
git add api/server/services/MCP.js api/server/services/__tests__/MCPConfirmation.spec.js
git commit -m "$(cat <<'EOF'
mcp: fire-and-forget clear of gateway pending approval on cancel/timeout

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Manual end-to-end smoke test (user-driven)

**Files:** none modified — verification only.

**Context:** This is the bug-reproduction sequence the user reported on 2026-05-09. After Tasks 1-3 land and both gateway + LibreChat are deployed, this sequence should NOT bypass the modal.

The user (Romuald) drives this. No subagent can do it — requires running gateway + LibreChat against a real MCP server.

- [ ] **Step 1: Build and start the gateway with the clear-feature commits**

```bash
cd /Users/romuald/Projects/FDJ-Projects/fdj-agentgateway
cargo build --release --bin agentgateway
./target/release/agentgateway --validate-only -f local.config.yaml
# Expected: "Configuration is valid!"
./target/release/agentgateway -f local.config.yaml &
```

- [ ] **Step 2: Build and start LibreChat with the clear-feature commits**

```bash
cd /Users/romuald/Projects/FDJ-Projects/Fdj-LibreChat
npm run build:api
# Plus whatever other build steps the project requires.
# (See agentgateway CLAUDE.md §7 for the canonical build sequence; nothing
#  changes for this feature.)
```

- [ ] **Step 3: Reproduce the original bug sequence**

In LibreChat, prompt the agent: *"send 'have a nice weekend' to both Joress Ngo and Romuald Esdras Wandji"*.

Two modals show in sequence (the queue model from the prior branch). **Decline both.**

Now, **within 60 seconds**, prompt the SAME thing again: *"send 'have a nice weekend' to both Joress Ngo and Romuald Esdras Wandji"*.

- [ ] **Step 4: Verify no bypass**

**Expected:** two modals show again. Gateway access logs show `duration=0ms` for both `tools/call` (Phase-1 envelopes), NOT `duration=200-400ms` (which would mean upstream forward bypassed confirmation). No Teams messages sent during the second prompt (until you actually click Approve).

If the modal does NOT show on the second prompt → STOP and capture: gateway logs from both rounds, browser devtools network tab + console, the LibreChat backend logs. The clear is not propagating.

- [ ] **Step 5: Repeat-cycle stress test**

Repeat decline-and-retry 3-5 times within a 90s window. Each cycle should show modals; no upstream calls until you actually click Approve. This proves the fix is robust to repeated decline scenarios, not a fluke that only worked once.

- [ ] **Step 6: Open PRs**

Once smoke passes, open the agentgateway PR and the Fdj-LibreChat PR. Reference the spec at `agentgateway/docs/superpowers/specs/2026-05-09-mcp-confirmation-clear-design.md` from both PR descriptions.

---

## Self-review (run after writing the plan)

**1. Spec coverage:**
- §1 problem & goal → Task 1+2 implement gateway side; Task 3 implements LibreChat side.
- §2 threat model → enforced structurally by the design (clear can only REMOVE entries; never approves).
- §3 wire format (sentinel arg in `tools/call`) → Task 2 implements gateway side; Task 3 emits.
- §3.1 sentinel name `__mcp_clear_pending__` → Task 1 defines the constant, all later tasks reference it.
- §3.2 lookup-key derivation (re-use Phase-1's `enrichment.strip + hash_args`) → Task 2.
- §4.1-4.6 lifecycle scenarios → covered by the 4 gateway tests (Task 2) + 2 LibreChat tests (Task 3) + manual smoke.
- §5 behavior matrix → covered.
- §6.1 schema-collision refusal → Task 1.
- §6.2-6.6 edge cases (auth, rate-limit, arg-rewrite, enrichment, LLM-misuse) → enforced by the early short-circuit in Task 2 (bypasses ALL of them).
- §7 out-of-scope → reflected in plan scope (no retry, no bulk, no by-id clear, no audit fields).
- §8 decisions locked → all reflected.
- §9 file inventory → matches the File Structure table at the top of this plan.
- §10 test plan → all three sections covered.

**2. Placeholder scan:** Searched for "TODO", "TBD", "implement later", "fill in details" — none. Some test code has comment annotations like `/* CEL matches the tool */` and `/* args */` where the implementer needs to substitute the actual config — these are explicit "use the existing harness pattern" prompts, not placeholders.

**3. Type consistency:** `MCP_CLEAR_PENDING_SENTINEL` constant name used consistently across Tasks 1, 2, and the schema-collision check. JS sentinel string `__mcp_clear_pending__` used consistently in Task 3 and matches the Rust constant value.
