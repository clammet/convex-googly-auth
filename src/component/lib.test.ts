/// <reference types="vite/client" />
import { describe, expect, it } from "vitest";
import { api } from "./_generated/api.js";
import { initConvexTest } from "./setup.test.js";
import {
  isSessionExpired,
  DEFAULT_SESSION_ABSOLUTE_TTL_MS,
  DEFAULT_SESSION_IDLE_TTL_MS,
  SESSION_ROTATION_GRACE_MS,
  sha256,
} from "./shared.js";

const NOW = 1_700_000_000_000;

async function claimHashOf(claim: string): Promise<string> {
  return await sha256(claim);
}

describe("identity transitions", () => {
  it("finds or creates anonymous identities by claim hash", async () => {
    const t = initConvexTest();
    const claimHash = await claimHashOf("a".repeat(64));

    const first = await t.mutation(api.lib.ensure, { claimHash, now: NOW });
    expect(first.created).toBe(true);

    const second = await t.mutation(api.lib.ensure, { claimHash, now: NOW });
    expect(second.created).toBe(false);
    expect(second.identityId).toBe(first.identityId);

    expect(await t.query(api.lib.resolve, { claimHash })).toBe(
      first.identityId,
    );
  });

  it("requires a credential", async () => {
    const t = initConvexTest();
    await expect(t.mutation(api.lib.ensure, { now: NOW })).rejects.toThrow();
  });

  it("upgrades an anonymous identity in place and retires the claim", async () => {
    const t = initConvexTest();
    const claimHash = await claimHashOf("b".repeat(64));
    const anon = await t.mutation(api.lib.ensure, { claimHash, now: NOW });

    const upgraded = await t.mutation(api.lib.ensure, {
      googleSubject: "google|alice",
      claimHash,
      now: NOW,
    });
    // Same identity id: app data keyed by it needs no migration.
    expect(upgraded.identityId).toBe(anon.identityId);
    expect(upgraded.upgraded).toBe(true);
    expect(upgraded.mergedFromId).toBeNull();

    // The retired claim must never authorize again.
    expect(await t.query(api.lib.resolve, { claimHash })).toBeNull();

    // Whoever still holds the old claim gets a fresh identity, not Alice's.
    const stale = await t.mutation(api.lib.ensure, { claimHash, now: NOW });
    expect(stale.created).toBe(true);
    expect(stale.identityId).not.toBe(anon.identityId);
  });

  it("absorbs an anonymous identity into an existing Google identity", async () => {
    const t = initConvexTest();
    const claimHash = await claimHashOf("c".repeat(64));
    const anon = await t.mutation(api.lib.ensure, { claimHash, now: NOW });
    const google = await t.mutation(api.lib.ensure, {
      googleSubject: "google|bob",
      now: NOW,
    });

    const merged = await t.mutation(api.lib.ensure, {
      googleSubject: "google|bob",
      claimHash,
      now: NOW,
    });
    expect(merged.identityId).toBe(google.identityId);
    expect(merged.mergedFromId).toBe(anon.identityId);
    expect(await t.query(api.lib.resolve, { claimHash })).toBeNull();
  });

  it("refuses to re-point a Google-backed identity at another account", async () => {
    const t = initConvexTest();
    const claimHash = await claimHashOf("d".repeat(64));
    const victim = await t.mutation(api.lib.ensure, { claimHash, now: NOW });
    await t.mutation(api.lib.ensure, {
      googleSubject: "google|victim",
      claimHash,
      now: NOW,
    });

    // The attacker knows the victim's old claim and signs in with their own
    // Google account. They must get their own identity, and the victim's
    // Google credential must be untouched.
    const attacker = await t.mutation(api.lib.ensure, {
      googleSubject: "google|attacker",
      claimHash,
      now: NOW,
    });
    expect(attacker.identityId).not.toBe(victim.identityId);
    expect(attacker.mergedFromId).toBeNull();

    const victimResolved = await t.query(api.lib.resolve, {
      googleSubject: "google|victim",
    });
    expect(victimResolved).toBe(victim.identityId);
  });

  it("never lets a claim on a dual-credential identity authorize (legacy import guard)", async () => {
    const t = initConvexTest();
    const claimHash = await claimHashOf("e".repeat(64));
    // Simulates data imported from the old schema where one row held both
    // credentials — the shape behind the original hijacking bug.
    const legacyId = await t.run(async (ctx) => {
      const identityId = await ctx.db.insert("identities", { createdAt: NOW });
      await ctx.db.insert("googleCredentials", {
        identityId,
        googleSubject: "google|legacy",
      });
      await ctx.db.insert("anonymousCredentials", { identityId, claimHash });
      return identityId;
    });

    expect(await t.query(api.lib.resolve, { claimHash })).toBeNull();

    // Presenting the stale claim retires it and mints a fresh identity
    // instead of handing back the Google-backed one.
    const result = await t.mutation(api.lib.ensure, { claimHash, now: NOW });
    expect(result.created).toBe(true);
    expect(result.identityId).not.toBe(legacyId);
    expect(
      await t.query(api.lib.resolve, { googleSubject: "google|legacy" }),
    ).toBe(legacyId);
  });
});

describe("session lifetime", () => {
  const base = { lastUsedAt: NOW, expiresAt: NOW + DEFAULT_SESSION_ABSOLUTE_TTL_MS };

  it("expires at the absolute deadline even while in active use", () => {
    const session = {
      ...base,
      lastUsedAt: NOW + DEFAULT_SESSION_ABSOLUTE_TTL_MS - 1000,
    };
    expect(
      isSessionExpired(session, NOW + DEFAULT_SESSION_ABSOLUTE_TTL_MS - 1),
    ).toBe(false);
    expect(
      isSessionExpired(session, NOW + DEFAULT_SESSION_ABSOLUTE_TTL_MS),
    ).toBe(true);
  });

  it("expires after the idle window despite a distant absolute deadline", () => {
    expect(isSessionExpired(base, NOW + DEFAULT_SESSION_IDLE_TTL_MS - 1)).toBe(
      false,
    );
    expect(isSessionExpired(base, NOW + DEFAULT_SESSION_IDLE_TTL_MS)).toBe(
      true,
    );
  });

  it("honors a custom idle window", () => {
    const hour = 60 * 60 * 1000;
    expect(isSessionExpired(base, NOW + hour - 1, hour)).toBe(false);
    expect(isSessionExpired(base, NOW + hour, hour)).toBe(true);
  });

  it("stores, rotates, and removes sessions", async () => {
    const t = initConvexTest();
    await t.mutation(api.lib.createSession, {
      sessionToken: "session-1",
      refreshToken: "refresh-1",
      googleSubject: "google|alice",
      now: NOW,
    });

    expect(
      await t.query(api.lib.getActiveSession, {
        sessionToken: "session-1",
        now: NOW + 1000,
      }),
    ).toEqual({ googleSubject: "google|alice", refreshToken: "refresh-1" });

    // Rotating within the idle window slides it and installs the new token.
    const midway = NOW + DEFAULT_SESSION_IDLE_TTL_MS - 1000;
    expect(
      await t.mutation(api.lib.rotateSession, {
        sessionToken: "session-1",
        newSessionToken: "session-1b",
        now: midway,
      }),
    ).toEqual({ sessionToken: "session-1b" });
    expect(
      await t.query(api.lib.getActiveSession, {
        sessionToken: "session-1b",
        now: midway + DEFAULT_SESSION_IDLE_TTL_MS - 1000,
      }),
    ).not.toBeNull();

    const removed = await t.mutation(api.lib.removeSession, {
      sessionToken: "session-1b",
      now: midway,
    });
    expect(removed).toEqual({ refreshToken: "refresh-1" });
    expect(
      await t.query(api.lib.getActiveSession, {
        sessionToken: "session-1b",
        now: midway,
      }),
    ).toBeNull();
  });

  it("honors the retired token only within the rotation grace window", async () => {
    const t = initConvexTest();
    await t.mutation(api.lib.createSession, {
      sessionToken: "session-r",
      refreshToken: "refresh-r",
      googleSubject: "google|alice",
      now: NOW,
    });
    await t.mutation(api.lib.rotateSession, {
      sessionToken: "session-r",
      newSessionToken: "session-r2",
      now: NOW + 1000,
    });

    // A racing refresh presenting the retired token is not rotated again;
    // it is handed the already-current token.
    const inGrace = NOW + 1000 + SESSION_ROTATION_GRACE_MS - 1;
    expect(
      await t.query(api.lib.getActiveSession, {
        sessionToken: "session-r",
        now: inGrace,
      }),
    ).not.toBeNull();
    expect(
      await t.mutation(api.lib.rotateSession, {
        sessionToken: "session-r",
        newSessionToken: "session-r3",
        now: inGrace,
      }),
    ).toEqual({ sessionToken: "session-r2" });

    // Past the grace window the retired token is dead; the current one lives.
    const afterGrace = NOW + 1000 + SESSION_ROTATION_GRACE_MS;
    expect(
      await t.query(api.lib.getActiveSession, {
        sessionToken: "session-r",
        now: afterGrace,
      }),
    ).toBeNull();
    expect(
      await t.query(api.lib.getActiveSession, {
        sessionToken: "session-r2",
        now: afterGrace,
      }),
    ).not.toBeNull();
  });

  it("refuses and deletes an idle-expired session on rotation", async () => {
    const t = initConvexTest();
    await t.mutation(api.lib.createSession, {
      sessionToken: "session-2",
      refreshToken: "refresh-2",
      googleSubject: "google|alice",
      now: NOW,
    });
    const later = NOW + DEFAULT_SESSION_IDLE_TTL_MS + 1;
    expect(
      await t.query(api.lib.getActiveSession, {
        sessionToken: "session-2",
        now: later,
      }),
    ).toBeNull();
    expect(
      await t.mutation(api.lib.rotateSession, {
        sessionToken: "session-2",
        newSessionToken: "session-2b",
        now: later,
      }),
    ).toBeNull();
    const sessions = await t.run(
      async (ctx) => await ctx.db.query("authSessions").collect(),
    );
    expect(sessions).toHaveLength(0);
  });

  it("applies configured TTLs", async () => {
    const t = initConvexTest();
    const hour = 60 * 60 * 1000;
    await t.mutation(api.lib.createSession, {
      sessionToken: "session-3",
      refreshToken: "refresh-3",
      googleSubject: "google|alice",
      now: NOW,
      absoluteTtlMs: 2 * hour,
    });
    expect(
      await t.query(api.lib.getActiveSession, {
        sessionToken: "session-3",
        now: NOW + hour - 1,
        idleTtlMs: hour,
      }),
    ).not.toBeNull();
    expect(
      await t.query(api.lib.getActiveSession, {
        sessionToken: "session-3",
        now: NOW + hour,
        idleTtlMs: hour,
      }),
    ).toBeNull();
    // The absolute deadline stamped at creation wins over a long idle window.
    expect(
      await t.query(api.lib.getActiveSession, {
        sessionToken: "session-3",
        now: NOW + 2 * hour,
      }),
    ).toBeNull();
  });

  it("skips expired sessions when reusing a refresh token", async () => {
    const t = initConvexTest();
    await t.mutation(api.lib.createSession, {
      sessionToken: "old",
      refreshToken: "refresh-old",
      googleSubject: "google|alice",
      now: NOW - DEFAULT_SESSION_ABSOLUTE_TTL_MS - 1,
    });
    expect(
      await t.query(api.lib.latestRefreshTokenForSubject, {
        googleSubject: "google|alice",
        now: NOW,
      }),
    ).toBeNull();

    await t.mutation(api.lib.createSession, {
      sessionToken: "new",
      refreshToken: "refresh-new",
      googleSubject: "google|alice",
      now: NOW,
    });
    expect(
      await t.query(api.lib.latestRefreshTokenForSubject, {
        googleSubject: "google|alice",
        now: NOW + 1000,
      }),
    ).toEqual({ refreshToken: "refresh-new" });
  });

  it("cleanup deletes sessions past their absolute deadline and keeps live ones", async () => {
    const t = initConvexTest();
    await t.mutation(api.lib.createSession, {
      sessionToken: "stale",
      refreshToken: "r",
      googleSubject: "google|alice",
      now: NOW - DEFAULT_SESSION_ABSOLUTE_TTL_MS - 1,
    });
    await t.mutation(api.lib.createSession, {
      sessionToken: "live",
      refreshToken: "r",
      googleSubject: "google|alice",
      now: NOW,
    });

    const deleted = await t.mutation(api.lib.cleanupExpiredSessions, {
      now: NOW,
    });
    expect(deleted).toBe(1);
    const remaining = await t.run(
      async (ctx) => await ctx.db.query("authSessions").collect(),
    );
    expect(remaining).toHaveLength(1);
    expect(remaining[0].sessionToken).toBe("live");
  });
});
