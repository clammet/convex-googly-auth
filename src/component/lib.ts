import { v } from "convex/values";
import { mutation, query } from "./_generated/server.js";
import type { MutationCtx, QueryCtx } from "./_generated/server.js";
import type { Doc, Id } from "./_generated/dataModel.js";
import { api } from "./_generated/api.js";
import {
  DEFAULT_SESSION_ABSOLUTE_TTL_MS,
  isSessionExpired,
  SESSION_ROTATION_GRACE_MS,
} from "./shared.js";

const CLEANUP_BATCH_SIZE = 256;

async function googleCredentialForIdentity(
  ctx: QueryCtx,
  identityId: Id<"identities">,
): Promise<Doc<"googleCredentials"> | null> {
  return await ctx.db
    .query("googleCredentials")
    .withIndex("by_identityId", (q) => q.eq("identityId", identityId))
    .first();
}

async function anonymousCredentialByClaimHash(
  ctx: QueryCtx,
  claimHash: string,
): Promise<Doc<"anonymousCredentials"> | null> {
  return await ctx.db
    .query("anonymousCredentials")
    .withIndex("by_claimHash", (q) => q.eq("claimHash", claimHash))
    .unique();
}

/**
 * An anonymous credential may only authorize (or be claimed by a Google
 * sign-in) while its identity has no Google credential and has not been
 * merged away. Without this guard, anyone who learned another user's claim
 * could keep using it as a permanent password-less way into the upgraded
 * account — the bug class this component exists to prevent.
 */
async function isClaimable(
  ctx: QueryCtx,
  credential: Doc<"anonymousCredentials">,
): Promise<boolean> {
  const identity = await ctx.db.get("identities", credential.identityId);
  if (identity === null || identity.mergedIntoId !== undefined) {
    return false;
  }
  return (await googleCredentialForIdentity(ctx, credential.identityId)) === null;
}

/** Delete an anonymous credential that must never authorize again. */
async function retireAnonymousCredential(
  ctx: MutationCtx,
  credential: Doc<"anonymousCredentials">,
): Promise<void> {
  await ctx.db.delete("anonymousCredentials", credential._id);
}

export const resolve = query({
  args: {
    googleSubject: v.optional(v.string()),
    claimHash: v.optional(v.string()),
  },
  returns: v.union(v.id("identities"), v.null()),
  handler: async (ctx, args) => {
    const { googleSubject, claimHash } = args;
    if (googleSubject !== undefined) {
      const credential = await ctx.db
        .query("googleCredentials")
        .withIndex("by_googleSubject", (q) =>
          q.eq("googleSubject", googleSubject),
        )
        .unique();
      return credential?.identityId ?? null;
    }
    if (claimHash === undefined) {
      return null;
    }
    const credential = await anonymousCredentialByClaimHash(ctx, claimHash);
    if (credential === null || !(await isClaimable(ctx, credential))) {
      return null;
    }
    return credential.identityId;
  },
});

const ensureResultValidator = v.object({
  identityId: v.id("identities"),
  created: v.boolean(),
  upgraded: v.boolean(),
  mergedFromId: v.union(v.id("identities"), v.null()),
});

/**
 * Find-or-create the caller's identity, handling every transition between
 * anonymous and Google-backed:
 *
 * - unauthenticated + claim: find or create an anonymous identity.
 * - Google + no claimable claim: find or create a Google identity.
 * - Google (new) + claimable claim: upgrade the anonymous identity in place.
 *   The identity id is preserved, so app data keyed by it needs no migration.
 *   The claim credential is deleted — it must never authorize again.
 * - Google (existing) + claimable claim: absorb the anonymous identity into
 *   the Google one. The claim credential is deleted and the anonymous
 *   identity is marked merged; `mergedFromId` tells the app to reconcile its
 *   own data (move or alias rows keyed by the absorbed id).
 */
export const ensure = mutation({
  args: {
    googleSubject: v.optional(v.string()),
    claimHash: v.optional(v.string()),
    now: v.number(),
  },
  returns: ensureResultValidator,
  handler: async (ctx, args) => {
    const { googleSubject, claimHash, now } = args;

    if (googleSubject === undefined) {
      if (claimHash === undefined) {
        throw new Error("Either googleSubject or claimHash is required");
      }
      const credential = await anonymousCredentialByClaimHash(ctx, claimHash);
      if (credential !== null) {
        if (!(await isClaimable(ctx, credential))) {
          // A claim pointing at a Google-backed or merged identity predates
          // this schema's invariants (bad import). Retire it rather than
          // handing back the linked identity, then mint a fresh one below.
          await retireAnonymousCredential(ctx, credential);
        } else {
          await ctx.db.patch("identities", credential.identityId, {
            lastSeenAt: now,
          });
          return {
            identityId: credential.identityId,
            created: false,
            upgraded: false,
            mergedFromId: null,
          };
        }
      }
      const identityId = await ctx.db.insert("identities", {
        createdAt: now,
        lastSeenAt: now,
      });
      await ctx.db.insert("anonymousCredentials", { identityId, claimHash });
      return { identityId, created: true, upgraded: false, mergedFromId: null };
    }

    const googleCredential = await ctx.db
      .query("googleCredentials")
      .withIndex("by_googleSubject", (q) =>
        q.eq("googleSubject", googleSubject),
      )
      .unique();
    const claimCredential =
      claimHash === undefined
        ? null
        : await anonymousCredentialByClaimHash(ctx, claimHash);
    const claimableCredential =
      claimCredential !== null &&
      claimCredential.identityId !== googleCredential?.identityId &&
      (await isClaimable(ctx, claimCredential))
        ? claimCredential
        : null;

    if (googleCredential !== null) {
      await ctx.db.patch("identities", googleCredential.identityId, {
        lastSeenAt: now,
      });
      if (claimableCredential === null) {
        return {
          identityId: googleCredential.identityId,
          created: false,
          upgraded: false,
          mergedFromId: null,
        };
      }
      await retireAnonymousCredential(ctx, claimableCredential);
      await ctx.db.patch("identities", claimableCredential.identityId, {
        mergedIntoId: googleCredential.identityId,
      });
      return {
        identityId: googleCredential.identityId,
        created: false,
        upgraded: false,
        mergedFromId: claimableCredential.identityId,
      };
    }

    if (claimableCredential !== null) {
      // In-place upgrade: retiring the claim is what revokes the old
      // credential; leaving it in place would keep it valid as a second,
      // password-less way into the Google-backed identity.
      await retireAnonymousCredential(ctx, claimableCredential);
      await ctx.db.insert("googleCredentials", {
        identityId: claimableCredential.identityId,
        googleSubject,
      });
      await ctx.db.patch("identities", claimableCredential.identityId, {
        lastSeenAt: now,
      });
      return {
        identityId: claimableCredential.identityId,
        created: false,
        upgraded: true,
        mergedFromId: null,
      };
    }

    const identityId = await ctx.db.insert("identities", {
      createdAt: now,
      lastSeenAt: now,
    });
    await ctx.db.insert("googleCredentials", { identityId, googleSubject });
    return { identityId, created: true, upgraded: false, mergedFromId: null };
  },
});

export const createSession = mutation({
  args: {
    sessionToken: v.string(),
    refreshToken: v.string(),
    googleSubject: v.string(),
    now: v.number(),
    absoluteTtlMs: v.optional(v.number()),
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    await ctx.db.insert("authSessions", {
      sessionToken: args.sessionToken,
      refreshToken: args.refreshToken,
      googleSubject: args.googleSubject,
      createdAt: args.now,
      expiresAt:
        args.now + (args.absoluteTtlMs ?? DEFAULT_SESSION_ABSOLUTE_TTL_MS),
      lastUsedAt: args.now,
    });
    return null;
  },
});

/**
 * Find a session by its current token, or by its just-rotated-out previous
 * token while the rotation grace window is open. The grace path keeps a
 * refresh that raced a rotation (another tab) from being treated as invalid.
 */
async function sessionByPresentedToken(
  ctx: QueryCtx,
  presentedToken: string,
  now: number,
): Promise<Doc<"authSessions"> | null> {
  const current = await ctx.db
    .query("authSessions")
    .withIndex("by_sessionToken", (q) => q.eq("sessionToken", presentedToken))
    .unique();
  if (current !== null) {
    return current;
  }
  const rotated = await ctx.db
    .query("authSessions")
    .withIndex("by_previousSessionToken", (q) =>
      q.eq("previousSessionToken", presentedToken),
    )
    .unique();
  if (
    rotated === null ||
    rotated.rotatedAt === undefined ||
    now >= rotated.rotatedAt + SESSION_ROTATION_GRACE_MS
  ) {
    return null;
  }
  return rotated;
}

const activeSessionValidator = v.union(
  v.object({
    googleSubject: v.string(),
    refreshToken: v.string(),
  }),
  v.null(),
);

export const getActiveSession = query({
  args: {
    sessionToken: v.string(),
    now: v.number(),
    idleTtlMs: v.optional(v.number()),
  },
  returns: activeSessionValidator,
  handler: async (ctx, args) => {
    const session = await sessionByPresentedToken(
      ctx,
      args.sessionToken,
      args.now,
    );
    if (session === null || isSessionExpired(session, args.now, args.idleTtlMs)) {
      return null;
    }
    return {
      googleSubject: session.googleSubject,
      refreshToken: session.refreshToken,
    };
  },
});

/**
 * Slide the idle window and rotate the session token. Presenting the current
 * token installs `newSessionToken`; presenting the just-retired previous
 * token (a refresh that raced a rotation) only touches the session and hands
 * back the already-current token. Returns the token that is now current, or
 * null when the session is unknown or expired.
 */
export const rotateSession = mutation({
  args: {
    sessionToken: v.string(),
    newSessionToken: v.string(),
    now: v.number(),
    idleTtlMs: v.optional(v.number()),
  },
  returns: v.union(v.object({ sessionToken: v.string() }), v.null()),
  handler: async (ctx, args) => {
    const session = await sessionByPresentedToken(
      ctx,
      args.sessionToken,
      args.now,
    );
    if (session === null) {
      return null;
    }
    if (isSessionExpired(session, args.now, args.idleTtlMs)) {
      await ctx.db.delete("authSessions", session._id);
      return null;
    }
    if (session.sessionToken !== args.sessionToken) {
      await ctx.db.patch("authSessions", session._id, {
        lastUsedAt: args.now,
      });
      return { sessionToken: session.sessionToken };
    }
    await ctx.db.patch("authSessions", session._id, {
      sessionToken: args.newSessionToken,
      previousSessionToken: session.sessionToken,
      rotatedAt: args.now,
      lastUsedAt: args.now,
    });
    return { sessionToken: args.newSessionToken };
  },
});

export const removeSession = mutation({
  args: { sessionToken: v.string(), now: v.number() },
  returns: v.union(v.object({ refreshToken: v.string() }), v.null()),
  handler: async (ctx, args) => {
    const session = await sessionByPresentedToken(
      ctx,
      args.sessionToken,
      args.now,
    );
    if (session === null) {
      return null;
    }
    await ctx.db.delete("authSessions", session._id);
    return { refreshToken: session.refreshToken };
  },
});

/**
 * Google only returns a refresh token on the first consent. Returning users
 * reuse the newest live session's refresh token for their new session.
 */
export const latestRefreshTokenForSubject = query({
  args: {
    googleSubject: v.string(),
    now: v.number(),
    idleTtlMs: v.optional(v.number()),
  },
  returns: v.union(v.object({ refreshToken: v.string() }), v.null()),
  handler: async (ctx, args) => {
    const sessions = ctx.db
      .query("authSessions")
      .withIndex("by_googleSubject", (q) =>
        q.eq("googleSubject", args.googleSubject),
      )
      .order("desc");
    let inspected = 0;
    for await (const session of sessions) {
      if (!isSessionExpired(session, args.now, args.idleTtlMs)) {
        return { refreshToken: session.refreshToken };
      }
      inspected += 1;
      if (inspected >= 32) {
        break;
      }
    }
    return null;
  },
});

/**
 * Deletes sessions past their absolute deadline. Idle-expired sessions are
 * already refused by every read path and get removed here once their
 * absolute deadline passes. Call this from an app cron.
 */
export const cleanupExpiredSessions = mutation({
  args: { now: v.number() },
  returns: v.number(),
  handler: async (ctx, args) => {
    const expired = await ctx.db
      .query("authSessions")
      .withIndex("by_expiresAt", (q) => q.lt("expiresAt", args.now))
      .take(CLEANUP_BATCH_SIZE);
    for (const session of expired) {
      await ctx.db.delete("authSessions", session._id);
    }
    if (expired.length === CLEANUP_BATCH_SIZE) {
      await ctx.scheduler.runAfter(0, api.lib.cleanupExpiredSessions, {
        now: args.now,
      });
    }
    return expired.length;
  },
});
