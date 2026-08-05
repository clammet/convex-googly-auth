# Changelog

## Unreleased

- Session TTLs are configurable via `GooglyAuthOptions.sessionIdleTtlMs` /
  `sessionAbsoluteTtlMs`; defaults raised to 60 days idle / 180 days
  absolute (Google refresh tokens expire after ~6 months of disuse, so a
  longer absolute lifetime buys nothing). Exported constants renamed to
  `DEFAULT_SESSION_IDLE_TTL_MS` / `DEFAULT_SESSION_ABSOLUTE_TTL_MS`.
- Sign-in now uses `prompt=select_account` instead of forcing the consent
  screen on every login. When a refresh token is needed and none is stored,
  the callback transparently re-runs the flow with `prompt=consent` once
  (loop-guarded by a signed `consented` flag in the OAuth state).
- The refresh route rotates the session token on every refresh and returns
  the replacement as `sessionToken`; the retired token stays valid for a
  60-second grace window so concurrent tabs are not signed out.
  `touchSession` is replaced by `rotateSession`, and `removeSession` also
  accepts a within-grace retired token.

## 0.1.0

- Initial release: Google OIDC + optional anonymous identity component,
  extracted from the `upgallery` and `when` auth schemes.
  - Component-owned tables: `identities`, `googleCredentials`,
    `anonymousCredentials` (hashes only), `authSessions`.
  - `GooglyAuth` app-side class: `resolveIdentity`, `ensureIdentity`
    (in-place anonymous → Google upgrade, cross-identity merge signaling),
    `registerRoutes` (Google OAuth code flow, HMAC-signed session tokens,
    refresh with 30d absolute / 7d idle TTLs), `cleanupExpiredSessions`.
  - `createGooglyAuthClient` React factory: provider,
    `ConvexProviderWithAuth` adapter, anonymous claim cookie helpers,
    OAuth callback handling.
  - Per-app opt-out of anonymous identities (`{ anonymous: false }`).
  - Regression suite porting `when`'s anonymousId-hijacking fixes.
