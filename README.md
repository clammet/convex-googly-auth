# convex-googly-auth

A [Convex component](https://docs.convex.dev/components) providing the shared
"easy anonymous / Google account" identity scheme used by `upgallery` and
`when`: Google OIDC sign-in with server-held refresh tokens, plus optional
anonymous identities backed by a hashed bearer claim — with the
anonymous-credential-hijacking bug class fixed structurally, in one place.

## Security model

- **Google sign-in.** Google issues the ID token; Convex verifies issuer,
  audience, and signature via the app's `convex/auth.config.ts`. Refresh
  tokens never leave the component's `authSessions` table — the browser only
  holds an opaque HMAC-signed session token and exchanges it for fresh ID
  tokens through the refresh route. Every refresh rotates the session token
  (with a short grace window for racing tabs), so an exfiltrated token goes
  stale on the next refresh. Sessions expire after 180 days absolute /
  60 days idle by default; configure via `sessionAbsoluteTtlMs` /
  `sessionIdleTtlMs` on `new GooglyAuth(...)`. Sign-in uses
  `prompt=select_account`; the callback re-runs the flow with
  `prompt=consent` only when a refresh token is needed and none is stored.
- **Anonymous users (optional).** Identified by a 256-bit hex claim in a
  cookie. The claim is a bearer secret; only its SHA-256 hash is stored.
- **Structural hijack prevention.** Credentials live in their own tables
  (`googleCredentials`, `anonymousCredentials`) pointing at an `identities`
  row. Upgrading an anonymous account to Google sign-in *deletes* the
  anonymous credential row, so a retired claim cannot remain a second,
  password-less way into the account — the "profile carrying both
  identifiers" shape behind the original `anonymousId` hijacking bugs is
  unrepresentable, and a defensive guard retires legacy dual-credential rows
  on sight. The regression suite in `example/convex/auth.test.ts` and
  `src/component/lib.test.ts` pins all of this down.
- **Apps never see credentials.** The component hands the app an opaque
  `identityId` string; the app keys its own profile table by it. In-place
  upgrades keep the same `identityId`, so app data does not move when a user
  signs in.

## Installation

```bash
npm install convex-googly-auth
```

```ts
// convex/convex.config.ts
import { defineApp } from "convex/server";
import googlyAuth from "convex-googly-auth/convex.config.js";

const app = defineApp();
app.use(googlyAuth);
export default app;
```

```ts
// convex/auth.config.ts
export default {
  providers: [
    {
      domain: "https://accounts.google.com",
      applicationID: process.env.AUTH_GOOGLE_ID,
    },
  ],
};
```

Environment variables on the deployment: `AUTH_GOOGLE_ID`,
`AUTH_GOOGLE_SECRET`, `SITE_URL` (canonical web origin).

## Server usage

```ts
// convex/lib/auth.ts — one instance for the whole app
import { GooglyAuth } from "convex-googly-auth";
import { components } from "../_generated/api";

export const googly = new GooglyAuth(components.googlyAuth);
// Google-only app? Anonymous claims are then ignored server-side everywhere:
// export const googly = new GooglyAuth(components.googlyAuth, { anonymous: false });
```

```ts
// convex/profiles.ts — the app owns its profile table
export const ensureCurrent = mutation({
  args: { anonymousClaim: v.optional(v.string()) },
  handler: async (ctx, args) => {
    const result = await googly.ensureIdentity(ctx, args);
    // result.identityId  — key your profile row by this (index it!)
    // result.identity    — the verified Google UserIdentity, or null
    // result.upgraded    — anonymous identity gained Google sign-in in place
    // result.mergedFromId — an anonymous identity was absorbed into this
    //                       one; move or alias your rows keyed by it
    ...
  },
});

// In queries/mutations that need the caller:
const identityId = await googly.resolveIdentity(ctx, {
  anonymousClaim: args.anonymousClaim,
});
```

```ts
// convex/http.ts
const http = httpRouter();
googly.registerRoutes(http, {
  // All optional; defaults read AUTH_GOOGLE_ID / AUTH_GOOGLE_SECRET / SITE_URL.
  allowedOrigins: ["https://alt.example.com"],
  // Or check a table of custom domains:
  // isAllowedOrigin: async (ctx, origin) => { ... },
});
export default http;
```

Routes mounted (prefix configurable via `pathPrefix`): `GET /auth/google/start`,
`GET /auth/google/callback`, `POST /auth/refresh`, `POST /auth/sign-out`.
The callback redirects to `{origin}/auth/callback` on the web app.

Optionally add a cron calling `googly.cleanupExpiredSessions(ctx)`.

## React usage

```ts
// src/lib/authClient.ts
import { createGooglyAuthClient } from "convex-googly-auth/react";

export const authClient = createGooglyAuthClient({
  convexSiteUrl: import.meta.env.VITE_CONVEX_SITE_URL,
  googleClientId: import.meta.env.VITE_GOOGLE_CLIENT_ID,
  storagePrefix: "myapp",       // localStorage keys + claim cookie name
  // anonymous: false,          // must match the server-side option
});
```

```tsx
// main.tsx
<authClient.GoogleAuthProvider>
  <ConvexProviderWithAuth client={convex} useAuth={authClient.useConvexGooglyAuth}>
    <App />
  </ConvexProviderWithAuth>
</authClient.GoogleAuthProvider>
```

- `authClient.useGoogleAuth()` → `{ isLoading, isAuthenticated, signIn, signOut }`
- `authClient.useAnonymousClaim()` → the claim to pass to Convex functions
  (null in Google-only mode)
- On your `/auth/callback` page call `authClient.handleAuthCallback()` once
  and navigate to the returned `redirect` (see `example/src/App.tsx`)
- After a signed-in `ensure` succeeds, call `authClient.clearAnonymousClaim()`

The `example/` directory is a complete working app; run tests with
`npm test`. Consumers can register the component in their own `convex-test`
suites via `convex-googly-auth/test` (see `example/convex/setup.test.ts`).

## Migrating upgallery / when onto this component

Both apps keep their profile tables and authorization logic; only the
credential columns move into the component.

1. Add `identityId: v.string()` (indexed) to the profile table; keep
   app-only fields (display name, roles, timezone, ...).
2. Backfill: for each profile row, insert component rows —
   `googleSubject` → a `googleCredentials` row, live `anonymousClaimHash` /
   `anonymousId` → an `anonymousCredentials` row (hash `when`'s plaintext
   ids with SHA-256 → base64url first; **skip any anonymous credential on a
   row that also has a Google subject** — those are exactly the hijackable
   legacy rows). Store the returned identity id in `identityId`.
3. Replace `getCurrentProfile`-style helpers with
   `googly.resolveIdentity(...)` + a `by_identityId` profile lookup, and the
   profile-bootstrap/merge mutations with `googly.ensureIdentity(...)`,
   handling `mergedFromId` with the app's existing merge strategy
   (upgallery: alias rows; when: `moveProfileData`).
4. Replace the hand-rolled `/auth/*` HTTP routes with
   `googly.registerRoutes(http, ...)` (upgallery: pass an `isAllowedOrigin`
   callback that checks `galleryHosts`), and the frontend
   `googleAuth.tsx` / claim helpers with `createGooglyAuthClient`.

Notes:

- Signing keys are derived from `AUTH_GOOGLE_SECRET` plus a
  `signingNamespace` (default `"googly-auth"`), so existing sessions and
  in-flight OAuth states are invalidated at migration; users just sign in
  again.
- `when`'s localStorage UUID `anonymousId`s are not valid claims (claims are
  64-hex). Either accept that pre-migration anonymous visitors get fresh
  identities, or do a one-time in-app exchange: the server looks up the
  legacy id, attaches a fresh claim (which the client stores) to the same
  identity, then deletes the legacy id.
- Requires `convex >= 1.43`.

---

### Repository layout

- `src/component/` — the component: schema (identities, credentials,
  sessions) and functions. Has its own `_generated/`.
- `src/client/` — app-side `GooglyAuth` class and HTTP route registration
  (auth + env access happen in the app, not the component).
- `src/react/` — browser client factory.
- `src/test.ts` — `convex-test` registration helper (exported as
  `convex-googly-auth/test`).
- `example/` — working example app + the regression test suite.

### Development

```bash
npm install --ignore-scripts   # prepare runs a build; skip on first install
npm run build                  # or build:codegen with a configured deployment
npm test
npm run typecheck && npm run lint
```
