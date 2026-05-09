# MCP confirmation pending-approval clear — design (v1)

**Status:** draft for review
**Author:** Claude (Opus 4.7) under direction of Romuald Wandji
**Date:** 2026-05-09
**Repos:** agentgateway (protocol + gateway-side handling) + Fdj-LibreChat (client side).
**Builds on:** the two-phase MCP confirmation feature ([CLAUDE.md §3](../../../CLAUDE.md)) and the LibreChat queue model just shipped to `feat/mcp-confirmation-queue`. Neither is modified by this spec.

---

## 1. Problem & goal

The two-phase confirmation feature stores a pending-approval entry on the gateway side, keyed by `(tool_name, hash(stripped_args))`, with a 120s TTL. The intended lifecycle:

1. **Phase 1.** Gateway receives `tools/call`, returns a confirmation envelope, stores the pending entry. LibreChat backend intercepts the envelope and awaits a user decision.
2. **Phase 2.** User approves; LibreChat backend re-issues the same `tools/call` with identical args. Gateway sees the matching pending entry, removes it, forwards upstream.

The bug: when the user **declines** (or the user's TTL fires), the LibreChat backend returns a synthetic canceled stub to the LLM but does NOT signal the gateway. **The gateway-side pending entry stays in `pending_approvals` for the full 120s TTL.** If the LLM (or user, prompting again) re-issues the same `(tool, args)` within that window, the gateway treats it as Phase 2 and forwards upstream — **silently bypassing the user's decline**.

Concretely observed in production-like testing on 2026-05-09:
- Round 1: user said "send X to A and B." Two parallel modals showed (queue model worked). User declined both. Gateway logs: `duration=0ms` for both `tools/call` (Phase-1 envelopes returned, no upstream forward).
- Round 2 (~26s later): user said the same thing again. Two `tools/call` arrived. Gateway logs: `duration=280ms` and `duration=300ms` — both forwarded upstream to Teams. **No modals shown. Both messages sent.**

**Goal of v1.** Add an explicit "clear pending approval" signal from LibreChat to gateway. When the LibreChat backend returns a canceled stub, it first issues a clear that removes the matching gateway-side pending entry. The 120s TTL becomes a fallback for failure cases, not the primary mechanism.

**Non-goals.**
- Bulk-clear ("clear all my pending"). One clear per `(tool, args)`.
- Retry / async background re-clear if the clear call fails. Best-effort only; TTL is the fallback.
- Cross-user or cross-session clearing. The clear is scoped to the same MCP session as the original Phase-1 call.

---

## 2. Threat model

The clear call only **removes** an entry; it does not approve one. So the worst-case for an attacker calling clear maliciously is: the user clicks Approve, the gateway has no matching pending entry, it returns a fresh Phase-1 envelope, the user sees another modal — annoying (a denial-of-service against approval), not exploitable.

The clear call uses the same authenticated MCP transport as `tools/call`, so any client able to issue tool calls can also issue clears for entries it itself created. There is no new auth surface.

The fix strengthens the user-decline guarantee: **decline now means decline**, not "decline-this-time-but-approve-on-retry-within-120s."

---

## 3. Wire format — sentinel arg in `tools/call`

The clear is issued as a normal `tools/call` request, with the same `name` (tool short name) and `arguments` as the original Phase-1 call, **plus** an additional sentinel arg:

```json
{
  "jsonrpc": "2.0",
  "id": "<req-id>",
  "method": "tools/call",
  "params": {
    "name": "send-chat-message",
    "arguments": {
      "chatId": "19:abc...@unq.gbl.spaces",
      "body": { "body": { "content": "have a nice weekend", "contentType": "text" } },
      "recipientDisplayName": "Joress Ngo",
      "__mcp_clear_pending__": true
    }
  }
}
```

The gateway:
1. Parses the `tools/call` as usual.
2. Detects the `__mcp_clear_pending__: true` arg.
3. Strips that arg out of `arguments`, then computes the same `(name, hash(stripped_args))` key as Phase-1 / Phase-2 use.
4. Removes the matching pending entry from `pending_approvals` if present (no-op if absent).
5. Returns a `CallToolResult::success` whose first text content is the JSON string `{"cleared": true}` (entry was found and removed) or `{"cleared": false}` (no matching entry — already consumed by Phase 2, never existed, or args don't match). No `reason` field in v1; LibreChat uses the boolean only.
6. **Never forwards upstream.** This is the load-bearing property — the upstream MCP server should not see a fake call.

The sentinel is intercepted **before** the existing confirmation-block logic runs. If the sentinel is present, the call is a clear; nothing else applies (no rate-limit, no auth filter against the resource — the auth that already covered the originating Phase-1 call is sufficient since the sentinel only operates on entries that came from the same authenticated client).

### 3.1 Why a sentinel arg, not a custom MCP method

| Option | Pros | Cons |
|---|---|---|
| **Sentinel arg in `tools/call`** (chosen) | Reuses existing transport + auth + interception hook in `session.rs`; no new method that downstream MCP libraries might reject | Slight overload of `tools/call` semantics; sentinel arg name needs to be carefully chosen to avoid collision with real tool args |
| Custom method `_meta/clearMcpConfirmation` | Cleaner semantically | Both ends must support it; some MCP relays might strip non-standard methods; new code path entirely |
| Repurpose `notifications/cancelled` | Native MCP concept | Wrong semantics — that notification is for in-flight request cancellation by id, not for resource-state cleanup |

**Sentinel name:** `__mcp_clear_pending__`. The double-underscore prefix matches Python-conventional "private" namespacing and is unlikely to be a legitimate parameter on any real MCP tool (a quick survey of public MCP tool definitions confirms none use underscore-prefixed property names). The gateway should reject any tool config whose schema declares this name as a real property — see §6.1.

### 3.2 Why pass `(toolName, args)` and re-derive the key, not pass an opaque key

The Phase-1 envelope already contains the args (echoed in `preview` and `presentation`). Adding an opaque `_pendingApprovalKey` to the envelope is a new contract surface. Re-deriving the key by reusing the same `enrichment.strip + hash_args` path that Phase-1 / Phase-2 already use is symmetric: any divergence between Phase-1's and clear's hashing would also break Phase-2, so testing one tests both.

---

## 4. Lifecycle (canonical happy & sad paths)

### 4.1 Decline (the main bug fix)

```
LLM ──► tools/call(name, args) ──► gateway
                                       │
                                       │ Phase 1: store pending
                                       │ ((name, hash(stripped_args)) → entry, TTL 120s)
                                       │
                       ◄───────────────┤ envelope (confirmationRequired: true)
LibreChat backend
  parses envelope, registers ConfirmationStore entry, emits SSE
                                       │
                       User clicks Decline (or auto-cancel on TTL)
                                       │
                                       ▼
LibreChat backend
  ── NEW STEP ─────────────────────────
  mcpManager.callTool(name, { ...originalArgs, __mcp_clear_pending__: true })
                                       │
                                       ▼
                                   gateway
                                       │
                                       │ Sees sentinel → strip sentinel from args
                                       │ → re-hash → look up pending entry
                                       │ → remove if present
                                       │ → return { cleared: true|false }
                                       │
                       ◄───────────────┤
LibreChat backend
  ignores result (best-effort), returns synthetic canceled stub to LLM
LLM ◄── canceled stub ◄── LibreChat backend
```

Now: if the LLM (or user) retries the same `(tool, args)` within 120s, the gateway has no pending entry → falls through to Phase 1 → fresh envelope → modal shown again. Decline is honored.

### 4.2 Approve (unchanged)

User clicks Approve → LibreChat backend issues a re-call WITHOUT the sentinel → gateway sees matching pending entry → Phase 2 → forwards upstream → entry consumed. Same flow as today.

### 4.3 Clear-call failure (network error, gateway restart, etc.)

LibreChat backend logs the error, returns the canceled stub to the LLM anyway. Gateway-side pending entry persists until its TTL expires. **Strictly worse than the success path** (the bypass window remains for up to 120s) **but no worse than today** (which is exactly that situation). TTL fallback is what makes this acceptable as best-effort.

### 4.4 Race: clear arrives AFTER Phase 2 already consumed the entry

Phase 2's `approvals.remove(&key)` already cleared the entry. The clear's `remove` is a no-op (returns "no matching entry"). Returns success-cleared-false; LibreChat ignores it. Safe.

### 4.5 Race: clear arrives BEFORE Phase 1 finishes inserting

Cannot happen — the clear is issued by the LibreChat backend AFTER `awaitConfirmationDecision` resolves, which can only happen AFTER the Phase-1 envelope has been received (and therefore AFTER the gateway has inserted the entry).

### 4.6 Race: two parallel cancels for the same `(tool, args)`

The first clear removes the entry. The second clear's `remove` is a no-op. Both return success-cleared-true and success-cleared-false respectively. Safe.

---

## 5. Behavior matrix

| Scenario | Gateway action | Clear response | LibreChat behavior |
|---|---|---|---|
| User declines, retries within 120s | Remove entry | `{cleared: true}` | Returns canceled stub; on retry, modal shows again ✓ |
| User declines, doesn't retry | Remove entry | `{cleared: true}` | Returns canceled stub |
| User auto-cancel (TTL on LibreChat side) | Remove entry | `{cleared: true}` | Returns canceled stub |
| Clear network fails | (entry stays until TTL) | n/a | Logs, returns canceled stub anyway. TTL eventually evicts. |
| Clear arrives but entry already gone (Phase 2 raced ahead) | No-op | `{cleared: false}` | Logs at debug; returns canceled stub anyway |
| Clear arrives with mismatched args (LibreChat bug) | No-op | `{cleared: false}` | Same |
| Clear sent for a tool with no `mcpConfirmation` policy | No-op | `{cleared: false}` | Same |

---

## 6. Edge cases & defensive measures

### 6.1 Tool-config validation: refuse `__mcp_clear_pending__` as a real property name

If any MCP tool's input schema declares a property named `__mcp_clear_pending__`, the gateway must refuse to start (similar to how `mcpToolEnrichment` collisions are detected statically — see [docs/superpowers/specs/2026-05-05-tool-schema-injection-design.md](2026-05-05-tool-schema-injection-design.md) §10). Detection: in `Relay::merge_tools`, after auth filter and enrichment, scan `Tool.input_schema.properties` for `__mcp_clear_pending__`; if found, return an error from the `MergeFn`. This is a one-time startup-ish failure mode (well, first-tools/list-call, like the existing enrichment conflict detection).

### 6.2 Auth & authorization

The clear travels through the same `tools/call` path → same `mcpAuthorization` rules apply. But there's a subtle point: if the tool is auth-allowed (the user can call it), they can ALSO clear pending entries for it. That's correct — the clear can only target entries the same authenticated session created (because the entry was created by THIS session's Phase 1 call, and `pending_approvals` is per-session — see CLAUDE.md §3).

Wait — let me check. The `pending_approvals` is on the `Session` struct (per-MCP-session). So the clear necessarily targets the same session's entries. No cross-session impact. Confirmed safe.

### 6.3 Rate-limit policy interaction

`mcpRateLimit` rules count `tools/call` requests. A clear is technically a `tools/call`. **Decision for v1: clears DO NOT count against `mcpRateLimit`.** Sentinel-detection short-circuits the entire `tools/call` handler — including the rate-limit check — and dispatches straight to the clear path. Rationale: a clear is a side-effect-free state-cleanup; penalizing the user for cancelling a destructive call would punish exactly the safety-conscious behavior the feature exists to support. If clear-spam DoS becomes a concern in practice (it would only matter if a malicious LLM is *also* somehow forging Phase-1 entries to clear), v2 can add a `mcpRateLimit.count_clears: true` option.

This decision aligns with §3 ("If the sentinel is present, the call is a clear; nothing else applies").

### 6.4 Argument-rewrite policy interaction

`mcpArgRewrite` rules mutate args before forward. **Decision for v1:** since clears are NEVER forwarded upstream, arg-rewrite rules are NOT applied to them. The sentinel-detection happens BEFORE the existing arg-rewrite call site. (This means the args used for the hash lookup are the args as the LLM sent them, before rewrite — same as Phase 1's hashing input.)

### 6.5 Enrichment-field interaction

For the clear's hash computation, the gateway must apply the same `enrichment.strip` + `hash_args` sequence as Phase 1 did. The sentinel is stripped FIRST, then `enrichment.strip`, then `hash_args`. This way the hash is identical to what Phase 1 produced, regardless of whether the synthetic enrichment field is present in the clear's args (it should be, since LibreChat passes `...originalArgs`, but defense-in-depth).

### 6.6 What happens if the LLM ever calls clear directly?

The sentinel is documented (in CLAUDE.md and the spec) as a LibreChat-internal mechanism; the gateway does not advertise it in the tool's schema (in fact §6.1 forbids it). The LLM can't read the spec, but if it somehow stumbles onto the sentinel and includes it in a regular call, the result is: (a) the gateway treats it as a clear, (b) returns `{cleared: false}` if there's no matching entry (most likely case), (c) the LLM gets back this odd response, and (d) the upstream call doesn't happen. Mild confusion for the LLM, no security impact.

---

## 7. Out of scope (v1)

- **Retry-with-backoff on clear failure.** Per Pick C; TTL fallback is sufficient.
- **Bulk clear** ("clear all pending for this session" or "clear all"). Not needed for the bug at hand.
- **Clearing by `confirmationId` (LibreChat-side ID).** The gateway-side key is `(tool, args-hash)`; no point introducing a translation layer.
- **A new `mcpRateLimit.skip_clears` option.** Defer until usage indicates it's needed.
- **Telemetry/audit fields specifically for clears.** Existing `accessLog` already records all `tools/call`s; the sentinel will be visible in args.
- **Server-side notification or pub/sub for "user declined."** The clear is a request/response, not an event. Sufficient for v1.

---

## 8. Decisions locked for v1

1. **Method shape:** sentinel arg `__mcp_clear_pending__` in a `tools/call` request. Not a custom MCP method, not `notifications/cancelled`.
2. **Lookup key:** pass `(toolName, originalArgs minus sentinel)`, gateway re-derives the key via the same `enrichment.strip + hash_args` path as Phase 1/2.
3. **Failure mode:** best-effort. Clear failure → log + continue (return canceled stub anyway). Gateway TTL is the fallback.
4. **Forward upstream:** never. Sentinel is detected BEFORE forwarding logic.
5. **Auth:** uses existing `mcpAuthorization`; no new auth surface.
6. **Rate limit:** clears count against `mcpRateLimit`. Revisit only if it bites.
7. **Tool-schema collision:** refuse-to-serve any tool whose schema declares `__mcp_clear_pending__` as a property (same refuse-to-start posture as enrichment conflicts).
8. **Backwards compatibility:** gateway side ships first (recognizes the sentinel; LibreChat hasn't started using it yet → no-op for now). LibreChat ships after (starts using it). No flag-day coordination needed.

---

## 9. File inventory (estimate)

### 9.1 agentgateway (~80-120 LoC + tests)

| Path | Change |
|---|---|
| `crates/agentgateway/src/mcp/session.rs` | In the `tools/call` handler (around line 453, before the confirmation block): detect `__mcp_clear_pending__: true` in `call_arguments`. If present, strip the sentinel, compute the same hash key Phase-1 uses, remove the matching entry from `pending_approvals`, return a `CallToolResult::success` with `{cleared: true|false}`. Skip all subsequent logic (rate-limit, confirmation, arg-rewrite, upstream forward). |
| `crates/agentgateway/src/mcp/handler.rs` | In `merge_tools` (alongside the existing enrichment conflict check from spec [2026-05-05](2026-05-05-tool-schema-injection-design.md)): scan each tool's `input_schema.properties` for `__mcp_clear_pending__`. If found, return an error from the `MergeFn`. |
| `crates/agentgateway/src/mcp/mcp_tests.rs` | New tests: clear-removes-pending, clear-with-no-matching-entry, clear-not-forwarded-upstream, clear-doesnt-affect-other-tools, schema-collision-refuses-to-serve. |
| Constant `MCP_CLEAR_PENDING_SENTINEL: &str = "__mcp_clear_pending__";` | Defined once (e.g. in `session.rs` or `mcp/mod.rs`); referenced by both detection and validation. |

### 9.2 Fdj-LibreChat (~50-80 LoC + tests)

| Path | Change |
|---|---|
| `api/server/services/MCP.js` | In the wrapper inside `_call`, in the `awaitConfirmationDecision` cancel/timeout branch (before constructing the canceled-stub return value): issue `mcpManager.callTool(toolName, { ...callToolArgs, __mcp_clear_pending__: true }).catch((err) => { /* log + ignore */ })`. Fire-and-forget — do NOT await its result before returning the stub. |
| `packages/api/src/mcp/ConfirmationStore.ts` | No changes — the store's resolve/cancel semantics are unchanged. |
| `api/server/services/__tests__/MCPConfirmation.spec.js` | New integration test: cancel-issues-clear, cancel-clear-failure-doesnt-block-stub-return. |

**Cross-repo coordination:** ship gateway first (sentinel-recognition is additive, harmless if no client uses it). Ship LibreChat after (starts emitting clears). Both backwards-compatible.

---

## 10. Test plan

### 10.1 Unit (agentgateway, `rbac.rs::session_tests` mod or `mcp_tests.rs`)

1. **Phase 1 → clear → Phase 1 again** — Phase 1 inserts entry; clear removes it; second Phase 1 with same args inserts a fresh entry (proves removal worked).
2. **Clear with no matching entry** — returns `{cleared: false}`, no error.
3. **Clear is never forwarded upstream** — mock backend asserts it received zero calls when the request was a clear (sentinel present).
4. **Clear with sentinel does not run rate-limit, arg-rewrite, or confirmation paths** — assertions on internal counters / mocks.
5. **Schema collision refusal** — a tool whose schema declares `__mcp_clear_pending__` causes `merge_tools` to return Err.

### 10.2 Integration (LibreChat, `MCPConfirmation.spec.js`)

1. **User cancels → clear is issued** — verify `mcpManager.callTool` is called a second time with the sentinel, with the same other args.
2. **User cancels → canceled stub returned even if clear fails** — mock the second `callTool` to throw; assert the stub is still returned to the LLM.

### 10.3 Manual end-to-end (the bug we're fixing)

1. Start gateway + LibreChat with current config.
2. Prompt: "send X to A and B."
3. Two modals show in sequence; decline both.
4. **Wait < 120s**, prompt the same thing again.
5. **Expected:** two modals show again. Both `tools/call` are 0ms (Phase-1 envelopes), not 280ms+ (upstream forwards).
6. Decline again. Verify Teams chat received nothing.
7. Repeat the prompt-and-decline cycle 3-5 times within 120s. Each cycle should show modals; no upstream calls until user actually clicks Approve.

---

## 11. Pointers

- Two-phase confirmation: agentgateway/CLAUDE.md §3 (architecture), §5.1 (envelope contract), §11 (pitfalls).
- Existing pending_approvals key derivation: [crates/agentgateway/src/mcp/session.rs:460-470](../../../crates/agentgateway/src/mcp/session.rs#L460-L470).
- Existing Phase-2 consumption + remove: [crates/agentgateway/src/mcp/session.rs:464-478](../../../crates/agentgateway/src/mcp/session.rs#L464-L478).
- Existing strip+rewrite ordering for upstream forward: [crates/agentgateway/src/mcp/session.rs:482-487](../../../crates/agentgateway/src/mcp/session.rs#L482-L487).
- LibreChat backend wrapper: `Fdj-LibreChat/api/server/services/MCP.js` — search for `awaitConfirmationDecision` and `buildCanceledToolResult`.
- LibreChat ConfirmationStore: `Fdj-LibreChat/packages/api/src/mcp/ConfirmationStore.ts`.
