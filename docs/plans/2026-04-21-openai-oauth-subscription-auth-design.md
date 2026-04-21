# OpenAI OAuth/Subscription Authentication Design

## Goal

Add OAuth/subscription-based authentication to the existing Amplifier OpenAI provider module, so users with ChatGPT Plus/Pro subscriptions can use Amplifier without needing a platform API key.

## Background

Currently the OpenAI provider requires a platform API key for authentication. Users with ChatGPT Plus or Pro subscriptions are already paying for model access but cannot use that subscription through Amplifier. Other tools in the ecosystem (OpenAI Codex CLI, Letta, OpenClaw) have implemented OAuth-based authentication against the ChatGPT backend, demonstrating that subscription-based access is viable. Adding this path gives subscription holders a zero-cost way to use Amplifier with OpenAI models.

## Approach

**Auth strategy module pattern.** A new `oauth.py` file encapsulates all OAuth concerns and exposes a clean interface to the provider. The existing `__init__.py` gets a thin conditional at mount and client construction points. No separate provider subclass, no forked request logic.

This was chosen over a separate provider subclass (the pattern Letta uses) because maintaining two provider classes leads to divergence over time and doubles the surface area for bugs. The strategy module pattern keeps one provider with a clean internal seam — roughly 10-15 lines of conditional logic in the existing code, with all OAuth complexity isolated in its own file.

**Constraint:** The current API key path must keep working untouched. All changes are additive.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  __init__.py                         │
│                                                      │
│  get_info()  ── new ConfigField: auth_mode           │
│                                                      │
│  mount()     ── if subscription → oauth.load/login   │
│              ── if api_key      → existing path      │
│                                                      │
│  client      ── if subscription → OAuth client       │
│              ── if api_key      → existing client     │
│                                                      │
│  complete()  ── on 401 + subscription → refresh+retry│
└──────────────────────┬──────────────────────────────┘
                       │ imports
                       ▼
┌─────────────────────────────────────────────────────┐
│                   oauth.py                           │
│                                                      │
│  login()          — PKCE flow + browser + callback   │
│  load_tokens()    — read ~/.amplifier/openai-oauth   │
│  refresh_tokens() — POST refresh_token to /token     │
│  is_token_valid() — expiry check for init gate       │
│  CONSTANTS        — endpoints, client ID, scopes     │
└──────────────────────┬──────────────────────────────┘
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
| ChatGPT backend base URL | `https://chatgpt.com/backend-api/codex/responses` |
| Token file path | `~/.amplifier/openai-oauth.json` |

### Token Storage

Simple JSON file at `~/.amplifier/openai-oauth.json` with `0600` permissions:

```json
{
  "auth_mode": "oauth",
  "access_token": "<jwt>",
  "refresh_token": "<opaque>",
  "id_token": "<jwt>",
  "account_id": "<workspace-id>",
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

A conditional at the top of mount:

- If `auth_mode == "subscription"`: call into `oauth.py` to load stored tokens, check validity (one-time init check), initiate login flow if no tokens exist. Build the provider with the OAuth credentials.
- If `auth_mode == "api_key"` (or unset): existing behavior, completely untouched.

#### Client Construction Changes

The `client` property gets a conditional for OAuth mode:

```python
AsyncOpenAI(
    api_key=self._access_token,       # Bearer token
    base_url=CHATGPT_CODEX_BASE_URL,
    default_headers={"ChatGPT-Account-ID": self._account_id},
    max_retries=0,
)
```

The OpenAI SDK's `api_key` param is used as the Bearer token — this is what Codex CLI does after the RFC 8693 exchange. The `default_headers` kwarg injects the account ID header on every request. No custom HTTP client needed.

For API key mode, client construction is identical to today.

#### 401 Handling

A small addition to error handling in `complete()`: if the response is a 401 and we're in OAuth mode, call `oauth.refresh_tokens()`, rebuild the client with the new access token, and retry the request once. If refresh fails, surface the error cleanly as an `AuthenticationError` directing the user to re-authenticate.

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
  → Client constructed with OAuth credentials
  → Provider mounted successfully
```

### Normal Session (Tokens Valid)

```
mount() detects auth_mode == "subscription"
  → oauth.load_tokens() → tokens loaded
  → oauth.is_token_valid() → true
  → Provider stores access_token and account_id in memory
  → Client constructed with OAuth credentials
  → API calls proceed normally
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

The local callback server on `localhost:1455` might conflict with something else (or with a running Codex CLI). If the port is unavailable, the provider should try a small range of fallback ports and update the redirect URI accordingly, or fail with a clear message about the port conflict.

## Testing Strategy

- **Existing API key tests unchanged.** All current tests continue to pass without modification since the API key path is untouched.
- **Unit tests for `oauth.py`:** Test token serialization/deserialization, expiry checking, PKCE challenge generation, and token file permission enforcement. Mock the HTTP exchanges for login and refresh flows.
- **Integration test for auth mode switching:** Verify that the provider correctly selects the OAuth or API key path based on `auth_mode` config, and that the two modes are mutually exclusive.
- **401 retry test:** Mock a 401 response followed by a successful refresh, verify the request is retried exactly once. Mock a 401 with a failed refresh, verify `AuthenticationError` is raised.
- **Edge case tests:** Missing token file triggers login. Malformed token file triggers login. Port conflict produces a clear error.

## Scope of Changes

| Type | Path | Description |
|---|---|---|
| New file | `oauth.py` | Login flow, token storage, refresh, constants |
| Modified file | `__init__.py` | Conditional in `mount()`, conditional in `client` property, 401 retry wrapper, new config field in `get_info()` |
| Runtime artifact | `~/.amplifier/openai-oauth.json` | Created on first login (0600 permissions) |
| Unchanged | Everything else | Streaming, tool handling, model listing, existing tests |

## Reference Implementations Studied

- **OpenAI Codex CLI** (Rust) — Full PKCE + device code flow, RFC 8693 token exchange, `~/.codex/auth.json` storage
- **OpenClaw** (TypeScript) — Multi-provider OAuth with per-agent token sink, file-locked refresh, adapter pattern
- **Letta** (Python) — Dual-auth with separate provider type, OAuth credentials stored as JSON in encrypted DB column, separate httpx client for ChatGPT backend
- **Amplifier GitHub Copilot provider** — Env var token resolution, lazy client init, fail-closed security pattern

## Open Questions

1. **Device code flow for headless environments.** Should we support the device code flow (for headless/remote environments) in addition to the browser-based PKCE flow, or is browser-only sufficient for an initial implementation?

2. **RFC 8693 secondary token exchange.** Should we perform the RFC 8693 secondary token exchange (`id_token` → API-key-style token) that Codex CLI does, or is using the `access_token` directly as a Bearer token sufficient?

3. **Model listing in subscription mode.** Should model listing behave differently in subscription mode? The ChatGPT backend may not have a `/models` endpoint, which could mean using a hardcoded model list (as Letta does) rather than dynamic discovery.
