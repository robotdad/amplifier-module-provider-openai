# OAuth Subscription Auth Integration Findings

**Date:** 2026-04-22
**Branch:** `feat/oauth-subscription-auth`
**Status:** Partially working. Auth flow succeeds. API calls return empty responses.

---

## 1. Original Design Assumptions vs Reality

### What the design assumed

The design document (`2026-04-21-openai-oauth-subscription-auth-design.md`) was built on a
core assumption validated by OpenClaw's Node.js SDK usage:

> "The same SDK calls work for both auth modes -- only the client construction differs."
>
> ```
> | Auth Mode     | base_url                                   | SDK constructs                                       |
> |---------------|-------------------------------------------|------------------------------------------------------|
> | API key       | https://api.openai.com/v1 (default)       | https://api.openai.com/v1/responses                 |
> | Subscription  | https://chatgpt.com/backend-api/codex     | https://chatgpt.com/backend-api/codex/responses     |
> ```
>
> "This means no raw httpx, no separate HTTP client class, and no forked request path."

The design positioned this as a thin strategy module (`oauth.py`) with "roughly 10-15 lines
of conditional logic in the existing code, with all OAuth complexity isolated in its own file."

### What we actually found

The ChatGPT backend (`chatgpt.com/backend-api/codex/responses`) is **a distinct, undocumented,
private API surface** -- not the standard OpenAI Responses API behind a different URL.

Multiple independent sources confirm this:

- **chatgpt-codex-proxy** (Go, github.com/dzintt/chatgpt-codex-proxy): "This project depends
  on the private `chatgpt.com/backend-api/codex/*` surface. That surface is undocumented and
  may change at any time."
- **codex-backend-sdk** (Python, github.com/B4PT0R/codex-backend-sdk): "All responses are
  streamed over SSE -- the backend does not support non-streaming requests."
- **LiteLLM**: "The ChatGPT subscription backend rejects token limit fields and metadata.
  LiteLLM strips these fields for this provider."

#### Concrete differences discovered

| Aspect | Standard API (`api.openai.com/v1`) | ChatGPT Backend (`chatgpt.com/backend-api/codex`) |
|--------|-----------------------------------|--------------------------------------------------|
| **Streaming** | Optional | **Required** -- non-streaming returns `{"detail": "Stream must be set to true"}` |
| **`max_output_tokens`** | Supported | **Rejected** -- `{"detail": "Unsupported parameter: max_output_tokens"}` |
| **`temperature`** | Supported | **Rejected** (silently echoed as server default `1.0`) |
| **`truncation`** | Supported | **Rejected** -- `{"detail": "Unsupported parameter: truncation"}` |
| **`parallel_tool_calls`** | Supported | **Not supported** |
| **`include`** | Supported (`reasoning.encrypted_content`) | **Not supported** |
| **Native tool types** | `apply_patch`, `web_search_preview`, `file_search`, `code_interpreter` | **Rejected** -- `{"detail": "Unsupported tool type: apply_patch"}` |
| **`/models` endpoint** | Returns available models dynamically | **Does not exist** -- only `/responses` is available |
| **Content type in output** | `type: "output_text"` | **May return `type: "text"`** (Letta handles both) |
| **Required headers** | `Authorization: Bearer {key}` | `Authorization: Bearer {token}` + `ChatGPT-Account-Id` + `OpenAI-Beta: responses=v1` + `OpenAI-Originator: codex` |
| **SSE accumulation** | SDK `stream.get_final_response()` works | **SDK accumulator returns empty `output: []`** despite generating tokens |
| **Device code endpoint** | N/A | Expects **JSON** body, not form-encoded; returns `device_auth_id` not `device_code` |
| **Token exchange (device code)** | N/A | `redirect_uri` must be `{issuer}/deviceauth/callback`, not `localhost` |

The design's core SDK-compatibility assertion turned out to be wrong. The OpenAI Python SDK's
streaming response accumulator does not correctly reconstruct the output from the ChatGPT
backend's SSE events, resulting in `output: []` in the final response object despite tokens
being generated and consumed.

---

## 2. Complete Diff Summary

### Diff stats (main..feat/oauth-subscription-auth)

```
10 files changed, 5650 insertions(+), 50 deletions(-)

 README.md                                          |   71 +
 amplifier_module_provider_openai/__init__.py       |  309 ++-
 amplifier_module_provider_openai/_response_handling.py |    4 +-
 amplifier_module_provider_openai/oauth.py          |  701 +++++
 docs/plans/...design.md                            |  309 +++
 docs/plans/...implementation.md                    | 2698 ++++++++++++++++++
 pyproject.toml                                     |    1 +
 tests/test_oauth.py                                |  791 ++++++
 tests/test_subscription_auth.py                    |  669 +++++
 uv.lock                                            |  147 +-
```

### Commits grouped by category

#### Design & Planning (4 commits)

| Commit | Description |
|--------|-------------|
| `5692733` | docs: add OAuth/subscription auth design document |
| `ef1fd36` | docs: update OAuth design spec with investigation findings |
| `a89140f` | docs: add dual-path login (browser + device code) to OAuth design |
| `3c2b8c7` | docs: add OAuth subscription auth implementation plan |

#### Recipe Implementation -- Phase 1: oauth.py core (5 commits)

| Commit | Description |
|--------|-------------|
| `428c573` | feat(oauth): add constants and PKCE helpers |
| `8ae1843` | feat(oauth): add token save/load with file permissions |
| `8c41780` | feat(oauth): add token expiry validation |
| `460cd42` | feat(oauth): add token refresh with disk persistence |
| `e0f3a4d` | feat(oauth): add JWT account_id extraction |

#### Recipe Implementation -- Phase 2: oauth.py login flows (4 commits)

| Commit | Description |
|--------|-------------|
| `ce5b1d3` | feat(oauth): add shared token exchange helper |
| `154ae33` | feat(oauth): add device code authorization flow |
| `2bc7081` | feat(oauth): add browser PKCE authorization flow |
| `3526c39` | feat(oauth): add dual-path login orchestration |

#### Recipe Implementation -- Phase 3: __init__.py integration (6 commits)

| Commit | Description |
|--------|-------------|
| `11b9265` | feat(subscription): add auth_mode ConfigField to get_info() |
| `b782aa2` | feat(subscription): add auth_mode to init and subscription mount path |
| `e928d60` | feat(subscription): conditional client construction for OAuth mode |
| `a089eb8` | feat(subscription): hardcoded model list for subscription mode |
| `adfdf51` | feat(subscription): 401 handler with token refresh and retry |
| `16a1940` | feat(subscription): end-to-end integration tests |

#### Recipe Implementation -- Post-recipe fixes (2 commits)

| Commit | Description |
|--------|-------------|
| `17f0b2d` | style: remove unused sentinel variable from e2e test |
| `a6c4494` | fix: declare _401_retry_attempted in __init__ and use get_running_loop |

#### Manual Fixes -- Provider Add / ConfigField (3 commits)

| Commit | Description | Problem |
|--------|-------------|---------|
| `7ea1e60` | fix: make api_key ConfigField optional to support subscription auth mode | `api_key` was implicitly required, blocking subscription selection in provider manage UI |
| `f3882b8` | fix: use show_when to conditionally hide api_key/base_url fields in subscription mode | API key and base URL fields appeared even when subscription was chosen |
| `a77c1ee` | docs: add Local Development section to README | N/A |

#### Manual Fixes -- OAuth Login During mount() (3 commits)

| Commit | Description | Problem |
|--------|-------------|---------|
| `3c7a375` | fix: make OAuth login visible during mount and handle provider add lifecycle | `list_models()` called with `config={}` during provider add; login output swallowed by UI |
| `c4c0a28` | fix: skip browser flow in SSH sessions, use device code only | SSH detection via `SSH_CLIENT`/`SSH_TTY` env vars |
| `f730069` | fix: remove browser flow from login, device code only | SSH env vars empty in Amplifier process context; `webbrowser.open()` launched Chromium on Pi's physical display causing gray screen |

#### Manual Fixes -- Device Code Flow (4 commits)

| Commit | Description | Problem |
|--------|-------------|---------|
| `4906d6b` | fix: device code flow - JSON content type, correct field names, proper headers | Cloudflare 530 (bare `urllib` User-Agent); endpoint expects JSON not form-encoded; response field is `device_auth_id` not `device_code`; `interval` returns as string not int |
| `c34f859` | fix: device code polling, remove debug logging, deduplicate custom model | Polling got HTTP errors because `authorization_pending` comes as HTTP 403 with `deviceauth_authorization_unknown` error code, not as JSON 200 with `error` key |
| `abfc90b` | fix: handle direct token response from device code poll | Login assumed poll always returns `authorization_code`; may return tokens directly |
| `2103a7b` | fix: use server code_verifier and JSON for token exchange | Device code poll response contains server's own `code_verifier` -- must use it instead of locally-generated one |

#### Manual Fixes -- Token Exchange (2 commits)

| Commit | Description | Problem |
|--------|-------------|---------|
| `f3e9b9c` | fix: revert token exchange to form-encoded, add visible error reporting | Token exchange at `/oauth/token` is standard OAuth (form-encoded), not JSON like the device code endpoints; added stderr error reporting |
| `d33db0d` | fix: use correct redirect_uri for device code token exchange | Device code flow requires `redirect_uri={issuer}/deviceauth/callback`, not `localhost:1455/auth/callback`. Confirmed from Codex CLI Rust source `device_code_auth.rs:190-204`. |

#### Manual Fixes -- ChatGPT Backend Parameter Compatibility (5 commits)

| Commit | Description | Problem |
|--------|-------------|---------|
| `03ef9ae` | fix: strip max_output_tokens for ChatGPT subscription backend | `{"detail": "Unsupported parameter: max_output_tokens"}` |
| `b20df10` | fix: strip unsupported params and add required headers for ChatGPT backend | Added guards for `temperature`, forced `store=false`, added `OpenAI-Beta: responses=v1` and `OpenAI-Originator: codex` headers |
| `a1d92d0` | fix: strip truncation param for ChatGPT subscription backend | `{"detail": "Unsupported parameter: truncation"}` |
| `335b9dc` | fix: disable native tool types for ChatGPT subscription backend | `{"detail": "Unsupported tool type: apply_patch"}` -- all native tool types filtered for subscription mode |
| `aad7f3e` | fix: strip include and parallel_tool_calls params for ChatGPT subscription backend | Stripped `include` (reasoning.encrypted_content) and `parallel_tool_calls` |

#### Manual Fixes -- Response Parsing (3 commits)

| Commit | Description | Problem |
|--------|-------------|---------|
| `8749efe` | fix: handle 'text' content type from ChatGPT backend (not just 'output_text') | Letta handles both `output_text` and `text`; our parser only checked `output_text`. Fixed in 6 locations across `__init__.py` and `_response_handling.py`. |
| `bb2278b` | fix: use non-streaming for subscription mode (SDK stream accumulator returns empty output) | Tried `responses.create()` instead of `responses.stream()`. Backend rejected with `{"detail": "Stream must be set to true"}`. |
| `51735b0` | fix: manual SSE text accumulation for ChatGPT subscription backend | Iterate SDK streaming events manually, collect `response.output_text.delta` text, then patch into `get_final_response()` output. |

---

## 3. What Works

### OAuth Device Code Login Flow

The device code flow authenticates successfully against `auth.openai.com`:

1. POST to `/api/accounts/deviceauth/usercode` (JSON body, User-Agent header) returns
   `user_code`, `device_auth_id`, `interval`
2. User visits `auth.openai.com/codex/device` and enters the code
3. Poll `/api/accounts/deviceauth/token` (JSON body with `device_auth_id` + `user_code`)
   until success
4. Success response contains `authorization_code` + server-provided `code_verifier`
5. Exchange at `/oauth/token` (form-encoded, `redirect_uri={issuer}/deviceauth/callback`)
   returns `access_token`, `refresh_token`, `id_token`, `expires_in`
6. `account_id` extracted from `id_token` JWT claims
7. Tokens saved to `~/.amplifier/openai-oauth.json` with `0600` permissions

**Confirmed working in live testing.** Tokens exchange successfully and persist.

### Provider Mount with Subscription Mode

- `mount()` correctly branches on `auth_mode == "subscription"`
- Loads tokens from disk, validates expiry, attempts refresh, falls back to login
- Provider instance gets `_access_token` and `_account_id` set
- Client constructed with correct `base_url` and `default_headers`

### Auth Mode Selection via ConfigField

- `get_info()` exposes `auth_mode` as a `choice` field (api_key / subscription)
- `api_key` field has `required=False` and `show_when={"auth_mode": "api_key"}`
- `base_url` field has `show_when={"auth_mode": "api_key"}`
- Provider manage UI correctly presents the choice

### Hardcoded Model List for Subscription Mode

- `list_models()` returns static list when `auth_mode == "subscription"` or when
  no API key is available (handles `config={}` during `provider add`)
- Models: `gpt-5.4`, `gpt-5.4-pro`, `gpt-5.4-mini`, `gpt-5.4-nano`, `gpt-5.3-codex`
- Framework adds `custom` entry automatically

### Parameter Guards (All Subscription-Only, API Key Path Untouched)

Verified from session `c9eaa014` raw event data -- the `llm:request` event's `raw` field
confirmed these parameters were NOT sent in subscription mode:

| Parameter | Guard Location | Evidence |
|-----------|---------------|----------|
| `max_output_tokens` | `__init__.py:906` | Not in request raw |
| `temperature` | `__init__.py:906` | Not in request raw |
| `truncation` | `__init__.py:998` | Not in request raw |
| `parallel_tool_calls` | `__init__.py:989` | Not in request raw |
| `include` | `__init__.py:952` | Not in request raw |
| `store` | `__init__.py:918` | Set to `false` in request raw |

The values `temperature: 1.0`, `top_p: 0.98`, `frequency_penalty: 0.0`,
`presence_penalty: 0.0`, `truncation: "disabled"`, `top_logprobs: 0` that appeared in session
response data are **server echo-backs** (the server's applied defaults), not parameters we sent.

### Native Tool Type Filtering

- `apply_patch`, `web_search_preview`, `file_search`, `code_interpreter` all filtered out
  for subscription mode at two guard points in `_convert_tools_from_request()`

### Content Type Handling

- All 6 extraction locations across `__init__.py` and `_response_handling.py` now check for
  both `"output_text"` and `"text"` content types

### 401 Token Refresh Handler

- On `openai.AuthenticationError` in subscription mode, attempts one token refresh
- `_401_retry_attempted` guard prevents infinite recursion
- Falls through to normal error handling if refresh fails or not in subscription mode

---

## 4. What Doesn't Work Yet

### The Core Problem: Empty Response Output

**Sessions tested:** `088c1485`, `e9d5cbcc`, `c9eaa014`, `589ac414`

In every test session, the ChatGPT backend:
- Accepts the request (status: `"completed"`, no error)
- Reports token usage (e.g., `output_tokens: 204`, including `reasoning_tokens: 167`,
  leaving `37` text tokens)
- Returns `output: []` -- a completely empty output array

The OpenAI Python SDK's `stream.get_final_response()` does not correctly reconstruct the
output from the ChatGPT backend's SSE events.

**Current attempted fix** (`51735b0`): Iterate the SDK's streaming event iterator manually,
collecting text from `response.output_text.delta` events, then patching collected text into
the response object if `output` is empty. This has NOT been confirmed working -- the most
recent test session (`589ac414`, `c9eaa014`) still showed empty output.

**Open question:** Does the SDK's streaming event iterator actually surface
`response.output_text.delta` events from this backend, or does the SDK's internal parsing
also fail on the ChatGPT backend's SSE format?

---

## 5. Root Cause Analysis: Why The OpenAI SDK Doesn't Work

### Evidence from every working implementation

**None of the four known Python/Go/TypeScript implementations of the ChatGPT backend use the
OpenAI SDK for the request/response cycle:**

| Implementation | Language | HTTP Client | SSE Parsing |
|---------------|----------|-------------|-------------|
| **Letta** (`chatgpt_oauth_client.py`) | Python | Raw `httpx.AsyncClient().stream()` | Manual: reads SSE lines, accumulates `response.output_text.delta` events |
| **codex-backend-sdk** (`codex_client.py`) | Python | `requests.Session().post(stream=True)` | Manual: `iter_lines()` + JSON parse |
| **chatgpt-codex-proxy** | Go | `httpcloak.Client` (custom) | Manual: accumulates deltas, fallback chain (delta -> `output_text.done` -> `content_part.done` -> walk final response) |
| **LiteLLM** | Python | Custom ChatGPT provider | Strips incompatible params, custom response handling |

**OpenClaw** (TypeScript) does use the OpenAI Node.js SDK with `baseURL` override, but it is
the only one -- and it may handle the response differently in JavaScript.

### Why the SDK fails

The OpenAI Python SDK's `AsyncStream` class accumulates SSE events into a final response
object via an internal state machine. This state machine was designed for the standard
`api.openai.com/v1/responses` endpoint. The ChatGPT backend's SSE event stream has
differences that cause the accumulator to produce an empty `output` array:

1. **The content type in events may differ** -- the backend may emit `"text"` instead of
   `"output_text"` in some event types
2. **The event sequence may differ** -- the backend may not emit the events the SDK expects
   for output reconstruction
3. **The final `response.done` event structure may differ** -- the Go proxy has an explicit
   fallback chain to handle cases where delta events don't arrive and the content is only in
   the final event

### What Letta does specifically

From `letta/llm_api/chatgpt_oauth_client.py`:

```python
# Line 249: stream is REQUIRED
data["stream"] = True

# Lines 173-281: build_request_data() constructs a minimal payload
# ONLY these keys: model, input, store(=False), stream(=True),
# service_tier (conditional), instructions (conditional),
# tools (conditional), tool_choice (conditional), reasoning (conditional)

# Lines 305-340: _accumulate_sse_response() does manual SSE parsing
async for line in response.aiter_lines():
    if line.startswith("data: "):
        event = json.loads(line[6:])
        event_type = event.get("type", "")
        if event_type == "response.output_text.delta":
            text_parts.append(event.get("delta", ""))
        elif event_type == "response.done":
            # Extract usage from final event
```

Letta bypasses the OpenAI SDK entirely for the ChatGPT backend and does raw HTTP with manual
SSE line parsing. This is the approach that is known to work.

---

## 6. Recommended Path Forward

The evidence is unambiguous: the OpenAI Python SDK was not designed for the ChatGPT
subscription backend, and every working Python implementation bypasses the SDK for the
request/response cycle.

### Option A: Raw httpx for subscription mode (Recommended)

Use raw `httpx.AsyncClient` for subscription mode API calls, keeping the OpenAI SDK for API
key mode. This is what Letta does.

**What changes:**
- Add `httpx` as a dependency (already a transitive dependency of the `openai` SDK)
- In `_do_complete()`, when `auth_mode == "subscription"`:
  - Build the request payload manually (model, input, instructions, tools, reasoning, store=False, stream=True)
  - POST to `{base_url}/responses` with correct headers
  - Read SSE lines, accumulate `response.output_text.delta` events
  - Parse the final `response.done` event for usage/metadata
  - Construct a response object compatible with `_convert_to_chat_response()`
- All response conversion logic (`_convert_to_chat_response()`, `_response_handling.py`) is
  shared between both paths -- only the HTTP transport and SSE parsing differ

**Pros:** Proven to work (Letta, codex-backend-sdk, LiteLLM all do this). Clean separation.
**Cons:** Two HTTP code paths in `_do_complete()`. More code than the original design intended.

### Option B: Debug the SDK streaming event iterator

Before committing to raw httpx, investigate whether the SDK's streaming event iterator
actually surfaces the right events.

**What to do:**
- Add logging to capture **every** event yielded by the SDK's `async for event in stream:`
  iterator -- log `event.type`, and for `response.output_text.delta`, log `event.delta`
- Run a test against the live backend
- If the iterator does yield `response.output_text.delta` events with text, the manual
  accumulation code at `__init__.py:1100-1133` should work -- the bug is elsewhere
- If the iterator does NOT yield these events, the SDK's internal SSE parser is filtering
  them out, and Option A (raw httpx) is the only viable path

**Pros:** Minimal code change if it works. Keeps single SDK path.
**Cons:** May be wasted effort if the SDK's SSE parser is fundamentally incompatible.

### Option C: Use codex-backend-sdk as a dependency

Install `codex-backend-sdk` (pip package) and use it for subscription mode calls.

**Pros:** Already built and tested for this backend.
**Cons:** Third-party dependency on a single maintainer's package. May not be actively
maintained. Adds dependency management overhead.

### Recommendation

**Try Option B first** (15 minutes of diagnostic logging against the live backend). If the
SDK's iterator does NOT yield delta events, proceed immediately to **Option A** (raw httpx).
Option A is the safe bet that matches every proven implementation.

---

## 7. Other Findings

### The ChatGPT backend MAY have a `/models` endpoint

The chatgpt-codex-proxy README mentions a `/backend-api/codex/models` endpoint. This was not
tested. If it exists and returns available models with subscription auth, it could replace the
hardcoded `SUBSCRIPTION_MODELS` list.

### The `originator` header may need to match a whitelist

From pi-mono Issue #1828: the `originator` header is **enforced server-side** -- third-party
tools get 403 unless the originator matches a whitelist. Our current value is `"codex"`. The
Codex CLI uses `"codex_cli_rs"`. The VS Code extension uses `"codex_vscode"`. If the backend
starts rejecting `"codex"`, we may need to use a specific whitelisted value. This has not been
an issue in testing so far -- the 403 would be obvious -- but it's a risk with an undocumented
private API.

### Provider `add` flow does not call `mount()` -- OAuth login happens at session start only

The Amplifier app-cli's `configure_provider()` collects config fields and saves YAML. It does
NOT call `mount()`. The OAuth login flow lives in `mount()`, so first-time auth only happens
when the user starts an actual Amplifier session, not during `provider add`. This is acceptable
(similar to how the Copilot provider works -- auth happens at runtime) but is less ideal UX
than prompting during setup.

### The app-cli passes `config={}` when calling `list_models()` during `provider add`

`_try_instantiate_provider()` in `provider_loader.py` creates a provider with empty config.
Our `list_models()` handles this by checking `if not self._api_key:` and falling through to
the subscription model list. This is a framework behavior, not a bug -- every provider must
handle being instantiated without collected config.

### Token refresh is untested end-to-end

The refresh flow code exists and is unit-tested with mocks, but has not been verified against
the live `auth.openai.com/oauth/token` endpoint with a real refresh token. The access tokens
have a long enough lifetime that refresh has not been triggered during testing.

### Browser PKCE flow is disabled

The `login()` function currently only runs the device code flow. The browser PKCE flow was
removed after discovering that:
1. SSH env vars (`SSH_CLIENT`, `SSH_TTY`) are empty inside Amplifier's process context
2. `webbrowser.open()` launches on the machine's physical display, not the SSH client's
3. On a Raspberry Pi with HDMI, this opened Chromium on a monitor nobody was looking at,
   causing a "gray screen" hang

The browser flow code still exists in `start_browser_flow()` but is not called. Re-enabling
it requires a better detection mechanism for "can the user actually see a browser on this
machine" or making it config-driven.

### Temporary error reporting code in `__init__.py`

Lines 100-105 of `mount()` have `import sys` + `print(... file=sys.stderr)` for making OAuth
errors visible during mount. This was added as a debugging aid and should be cleaned up once
the core issues are resolved.

---

## 8. Session Evidence Log

| Session ID | Result | Key Finding |
|-----------|--------|-------------|
| `6d4be1a4` | Auth succeeded, provider mounted, 401 on API call | First successful auth -- but before parameter guards |
| `6e061d6a` | Provider not mounted | OpenAI provider never called -- used Anthropic only |
| `41e4534c` | Provider not mounted | Same -- Anthropic fallback because mount() failed silently |
| `088c1485` | `output: []`, 204 output tokens | First evidence of empty output array despite token generation |
| `e9d5cbcc` | `output: []`, 204 output tokens | Parameter guards confirmed working; server echo-backs identified |
| `c9eaa014` | `output: []`, 204 output tokens (167 reasoning, 37 text) | Full raw data analysis -- guards verified, empty output confirmed |
| `589ac414` | `output: []` | After manual SSE accumulation attempt -- still empty |
