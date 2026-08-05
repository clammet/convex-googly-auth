# Changelog

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
