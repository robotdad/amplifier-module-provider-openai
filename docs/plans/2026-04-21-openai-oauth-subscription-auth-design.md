# OpenAI OAuth/Subscription Authentication Design

## Goal

Add OAuth/subscription-based authentication to the existing Amplifier OpenAI provider module, so users with ChatGPT Plus/Pro subscriptions can use Amplifier without needing a platform API key.

## Background

Currently the OpenAI provider requires a platform API key for authentication. Users with ChatGPT Plus or Pro subscriptions are already paying for model access but cannot use that subscription through Amplifier. Other tools in the ecosystem (OpenAI Codex CLI, Letta, OpenClaw) have implemented OAuth-based authentication against the ChatGPT backend, demonstrating that subscription-based access is viable. Adding this path gives subscription holders a zero-cost way to use Amplifier with OpenAI models.

## Approach

**Auth strategy module pattern.** A new `oauth.py` file encapsulates all OAuth concerns and exposes a clean interface to the provider. The existing `__init__.py` gets a thin conditional at four touch points: `get_info()`, `mount()`, the `client` property, and `complete()` 401 handling. No separate provider subclass, no forked request logic.

This was chosen over a separate provider subclass (the pattern Letta uses) because maintaining two provider classes leads to divergence over time and doubles the surface area for bugs. The strategy module pattern keeps one provider with a clean internal seam — roughly 10-15 lines of conditional logic in the existing code, with all OAuth complexity isolated in its own file.

**Constraint:** The current API key path must keep working untouched. All changes are additive.

### SDK Compatibility

The existing Amplifier OpenAI provider already uses exclusively the Responses API (`client.responses.stream()` and `client.responses.create()`). When `base_url` is set to `https://chatgpt.com/backend-api/codex`, the OpenAI Python SDK constructs `https://chatgpt.com/backend-api/codex/responses` — which is exactly what the ChatGPT backend expects. OpenClaw confirms this works in production with the Node.js OpenAI SDK using the same pattern.

This means **no raw httpx, no separate HTTP client class, and no forked request path**. The same SDK calls work for both auth modes — only the client construction differs:

| Auth Mode | `base_url` | SDK constructs |
|-----------|-----------|----------------|
| API key | `https://api.openai.com/v1` (default) | `https://api.openai.com/v1/responses` |
| Subscription | `https://chatgpt.com/backend-api/codex` | `https://chatgpt.com/backend-api/codex/responses` |

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  __init__.py                             │
│                                                         │
│  get_info()  ── new ConfigField: auth_mode              │
│                                                         │
│  mount()     ── if subscription → oauth.load/login      │
│              ── if api_key      → existing path         │
│                                                         │
│  client      ── if subscription → OAuth client          │
│              ── if api_key      → existing client        │
│                                                         │
│  complete()  ── on 401 + subscription → refresh+retry   │
└──────────────────────┬──────────────────────────────────┘
                       │ imports
                       ▼
┌─────────────────────────────────────────────────────────┐
│                   oauth.py                              │
│                                                         │
│  login()          — PKCE flow + browser + callback      │
│  load_tokens()    — read ~/.amplifier/openai-oauth.json │
│  refresh_tokens() — POST refresh_token to /token        │
│  is_token_valid() — expiry check for init gate          │
│  CONSTANTS        — endpoints, client ID, scopes        │
└──────────────────────┬──────────────────────────────────┘
                       │ reads/writes
                       ▼
            ~/.amplifier/openai-oauth.json
                    (0600 perms)
```

## Components

### New File: `oauth.py`

Encapsulates all OAuth concerns. The rest of the provider imports from this module but never touches OAuth internals.

#### Login Flow

A `login()` function that runs the full PKCE authorization code flow:

1. Generate a PKCE code verifier + SHA256 challenge
2. Start a temporary local HTTP server on `localhost:1455` (matching the Codex CLI callback port)
3. Open the user's browser to `auth.openai.com/oauth/authorize` with standard scopes
4. Receive the authorization code on the callback
5. Exchange it for `id_token`, `access_token`, and `refresh_token` at `/oauth/token`
6. Extract the `account_id` from the `id_token` claims
7. Save everything to `~/.amplifier/openai-oauth.json`
8. Return the credentials

#### Token Management

- `load_tokens()` — Read stored tokens from the JSON file
- `refresh_tokens()` — Post the refresh token to `/oauth/token` to get new tokens
- `is_token_valid()` — Check if stored tokens exist and haven't expired (for one-time init check)

#### Constants

All OAuth-related constants in one place:

| Constant | Value |
|---|---|
| OAuth issuer | `https://auth.openai.com` |
| Authorize endpoint | `https://auth.openai.com/oauth/authorize` |
| Token endpoint | `https://auth.openai.com/oauth/token` |
| Client ID | `app_EMoamEEZ73f0CkXaXp7hrann` |
| Scopes | `openid profile email offline_access` |
| Callback URL | `http://localhost:1455/auth/callback` |
| ChatGPT backend base URL | `https://chatgpt.com/backend-api/codex` |
| Token file path | `~/.amplifier/openai-oauth.json` |

**Resolved: RFC 8693 secondary token exchange.** The RFC 8693 secondary token exchange (`id_token` → API-key-style token) performed by the Codex CLI is not needed. The OAuth `access_token` is used directly as a Bearer token against the ChatGPT backend endpoint. All three reference implementations (Codex CLI, Letta, OpenClaw) confirm the `access_token` is passed as the Bearer token for inference requests.

### Token Storage

Simple JSON file at `~/.amplifier/openai-oauth.json` with `0600` permissions:

```json
{
  "auth_mode": "oauth",
  "access_token": "<jwt>",
  "refresh_token": "<opaque>",
  "id_token": "<jwt>",
  "account_id": "<openai-account-id>",
  "expires_at": "<iso-timestamp>"
}
```

### Modified File: `__init__.py`

Surgical modifications at four points. Everything else in the file — streaming, tool handling, model listing — remains unchanged.

#### `get_info()` Changes

Add a new `ConfigField` for auth mode selection:

```python
ConfigField(
    id="auth_mode",
    display_name="Authentication Method",
    field_type="select",
    options=["api_key", "subscription"],
    default="api_key",
)
```

When the user picks `"subscription"`, the provider manage UI skips the API key prompt. When they pick `"api_key"`, behavior is identical to today.

#### `mount()` Changes

A conditional at the top of mount. Note: `mount()` handles credential loading and validation only — client construction is deferred to the lazy `client` property.

- If `auth_mode == "subscription"`: call into `oauth.py` to load stored tokens, check validity (one-time init check), attempt refresh if expired, initiate login flow if no tokens exist or refresh fails. Store the OAuth credentials (access token, account ID) on the provider instance.
- If `auth_mode == "api_key"` (or unset): existing behavior, completely untouched.

#### Client Construction Changes

The `client` property gets a conditional for OAuth mode:

```python
# Subscription mode
AsyncOpenAI(
    api_key=self._access_token,
    base_url="https://chatgpt.com/backend-api/codex",
    default_headers={"ChatGPT-Account-Id": self._account_id},
    max_retries=0,
)
```

The OpenAI SDK's `api_key` param is used as the Bearer token — the SDK sets `Authorization: Bearer {api_key}` on every request. The `default_headers` kwarg injects the `ChatGPT-Account-Id` header on every request. This header is **required** for subscription auth — all three reference implementations (Codex CLI, Letta, OpenClaw) send it. No custom HTTP client needed.

For API key mode, client construction is identical to today.

#### 401 Handling

A small addition to error handling in `complete()`: if the response is a 401 and we're in OAuth mode, call `oauth.refresh_tokens()`, rebuild the client with the new access token, and retry the request once. If refresh fails, surface the error cleanly as an `AuthenticationError` directing the user to re-authenticate.

**Streaming 401 handling:** If a 401 occurs mid-stream, the stream is aborted, tokens are refreshed, and the full request is retried from the beginning (not resumed from mid-stream). Partial streamed output from the failed attempt is discarded.

## Data Flow

### First-Time Setup (Subscription Mode)

```
User selects "subscription" in provider manage
  → mount() detects auth_mode == "subscription"
  → oauth.load_tokens() → no file found
  → oauth.login() starts
    → PKCE verifier/challenge generated
    → Local server binds localhost:1455
    → Browser opens auth.openai.com/oauth/authorize
    → User authenticates with OpenAI
    → Callback received with authorization code
    → Code exchanged at /oauth/token
    → Tokens + account_id saved to ~/.amplifier/openai-oauth.json (0600)
  → Provider stores access_token and account_id in memory
  → Provider mounted successfully (client constructed lazily on first use)
```

### Normal Session (Tokens Valid)

```
mount() detects auth_mode == "subscription"
  → oauth.load_tokens() → tokens loaded
  → oauth.is_token_valid() → true
  → Provider stores access_token and account_id in memory
  → Provider mounted successfully (client constructed lazily on first use)
  → API calls proceed normally
```

### Expired Tokens at Mount

```
mount() detects auth_mode == "subscription"
  → oauth.load_tokens() → tokens loaded
  → oauth.is_token_valid() → false (expired)
  → oauth.refresh_tokens() attempted
    → If refresh succeeds:
      → New tokens saved to ~/.amplifier/openai-oauth.json
      → Provider stores refreshed access_token and account_id in memory
      → Provider mounted successfully
    → If refresh fails (refresh token also expired/revoked):
      → oauth.login() starts (full browser-based PKCE flow)
      → Same flow as First-Time Setup from here
```

### Token Refresh (401 During Session)

```
API call returns 401
  → Provider detects OAuth mode
  → oauth.refresh_tokens() called
    → POST refresh_token to /oauth/token
    → New tokens saved to ~/.amplifier/openai-oauth.json
  → Client rebuilt with new access_token
  → Original request retried once
  → If refresh fails → AuthenticationError raised
```

## Error Handling

### Login Failures

If the OAuth login flow fails (user closes browser, network error, auth server rejects), the provider surfaces a clear error message and falls back to not mounting — same as today when an API key is missing. No partial state left behind.

### Refresh Failure During a Session

On a 401, the provider attempts one refresh. If the refresh itself fails (refresh token expired, revoked, network error), the provider raises an `AuthenticationError` with a message directing the user to re-authenticate via provider manage. It does not silently retry or loop.

### Corrupted or Missing Token File

If `~/.amplifier/openai-oauth.json` is missing, malformed, or has invalid data, the provider treats it the same as "no tokens stored" and initiates the login flow (since the user already chose subscription mode).

### Port Conflict

The local callback server binds `localhost:1455`. The OAuth client registration (`app_EMoamEEZ73f0CkXaXp7hrann`) has a fixed redirect URI (`http://localhost:1455/auth/callback`). Dynamic port fallback is **not possible** — using a different port would cause an OAuth redirect-URI mismatch error from the authorization server. If port 1455 is unavailable, the provider fails with a clear error message explaining the port conflict and suggesting the user free the port (e.g., close the Codex CLI if it's running on that port).

## Model Listing in Subscription Mode

In subscription mode, the ChatGPT backend does not expose a `/models` endpoint for dynamic model discovery. The initial implementation uses a hardcoded list of known subscription-available models (e.g., `gpt-5.4`, `gpt-5.3`, `gpt-5.2`, `o3`, `o4-mini`, etc.), similar to how Letta handles subscription model listing. This list is maintained as a constant in `oauth.py` and can be refined as the ChatGPT backend API matures. In API key mode, existing dynamic model listing behavior is unchanged.

## Testing Strategy

- **Existing API key tests unchanged.** All current tests continue to pass without modification since the API key path is untouched.
- **Unit tests for `oauth.py`:** Test token serialization/deserialization, expiry checking, PKCE challenge generation, and token file permission enforcement. Mock the HTTP exchanges for login and refresh flows.
- **Integration test for auth mode switching:** Verify that the provider correctly selects the OAuth or API key path based on `auth_mode` config, and that the two modes are mutually exclusive.
- **401 retry test:** Mock a 401 response followed by a successful refresh, verify the request is retried exactly once. Mock a 401 with a failed refresh, verify `AuthenticationError` is raised.
- **Streaming 401 test:** Mock a 401 mid-stream, verify the stream is aborted, tokens refreshed, and the full request retried from the beginning.
- **Edge case tests:** Missing token file triggers login. Malformed token file triggers login. Port conflict produces a clear error. Expired tokens at mount trigger refresh then fallback to login.

## Scope of Changes

| Type | Path | Description |
|---|---|---|
| New file | `oauth.py` | Login flow, token storage, refresh, constants, hardcoded model list |
| Modified file | `__init__.py` | Conditional in `mount()`, conditional in `client` property, 401 retry wrapper, new config field in `get_info()` |
| Runtime artifact | `~/.amplifier/openai-oauth.json` | Created on first login (0600 permissions) |
| Unchanged | Everything else | Streaming, tool handling, existing tests |

## Reference Implementations Studied

- **OpenAI Codex CLI** (Rust) — Full PKCE + device code flow, RFC 8693 token exchange, `~/.codex/auth.json` storage
- **OpenClaw** (TypeScript) — Multi-provider OAuth with per-agent token sink, file-locked refresh, adapter pattern. Confirms `AsyncOpenAI(base_url="https://chatgpt.com/backend-api/codex")` works with the standard SDK.
- **Letta** (Python) — Dual-auth with separate provider type, OAuth credentials stored as JSON in encrypted DB column, separate httpx client for ChatGPT backend (we avoid this approach by reusing the SDK)
- **Amplifier GitHub Copilot provider** — Env var token resolution, lazy client init, fail-closed security pattern

## Open Questions

1. **Device code flow for headless environments.** Should we support the device code flow (for headless/remote environments) in addition to the browser-based PKCE flow? **Disposition:** Out of scope for initial implementation. Browser-based PKCE is sufficient for the first version. Device code flow can be added as a follow-on for headless/remote environments.
