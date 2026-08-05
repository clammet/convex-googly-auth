import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

export default defineSchema({
  // One row per identity. Apps store `identityId` (as a string) on their own
  // profile rows; the id survives an anonymous -> Google upgrade, so app data
  // keyed by it never needs to move for the common single-account case.
  identities: defineTable({
    createdAt: v.number(),
    lastSeenAt: v.optional(v.number()),
    // Set when this identity was absorbed into another one at sign-in (the
    // caller already had a Google identity AND presented an anonymous claim).
    // The app is told about the merge and decides how to reconcile its data.
    mergedIntoId: v.optional(v.id("identities")),
  }).index("by_mergedIntoId", ["mergedIntoId"]),

  // Credentials live in their own tables, not as optional fields on the
  // identity. An identity holding both an anonymous claim and a Google
  // subject was the root cause of the anonymousId-hijacking bug class this
  // component exists to prevent: upgrading DELETES the anonymous credential
  // row, so a retired claim structurally cannot keep authorizing the account.
  googleCredentials: defineTable({
    identityId: v.id("identities"),
    // The OIDC token identifier (issuer|subject) from ctx.auth.
    googleSubject: v.string(),
  })
    .index("by_googleSubject", ["googleSubject"])
    .index("by_identityId", ["identityId"]),

  anonymousCredentials: defineTable({
    identityId: v.id("identities"),
    // SHA-256 of the client-held claim; the plaintext is never stored.
    claimHash: v.string(),
  })
    .index("by_claimHash", ["claimHash"])
    .index("by_identityId", ["identityId"]),

  // Google refresh tokens never leave this table. The browser only ever holds
  // an opaque, HMAC-signed session token that it exchanges for fresh ID
  // tokens through the refresh route.
  authSessions: defineTable({
    sessionToken: v.string(),
    refreshToken: v.string(),
    googleSubject: v.string(),
    createdAt: v.number(),
    expiresAt: v.number(),
    lastUsedAt: v.number(),
    // Every refresh rotates the session token, shrinking the window in which
    // an exfiltrated (e.g. via XSS) token stays useful. The retired token is
    // honored briefly so a racing refresh from another tab is not signed out.
    previousSessionToken: v.optional(v.string()),
    rotatedAt: v.optional(v.number()),
  })
    .index("by_sessionToken", ["sessionToken"])
    .index("by_previousSessionToken", ["previousSessionToken"])
    .index("by_googleSubject", ["googleSubject"])
    .index("by_expiresAt", ["expiresAt"]),
});
