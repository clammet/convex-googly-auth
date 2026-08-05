/// <reference types="vite/client" />
import { describe, expect, it } from "vitest";
import { api } from "./_generated/api.js";
import { initConvexTest } from "./setup.test.js";

const GOOGLE_ISSUER = "https://accounts.google.com";
const tokenIdentifier = (subject: string) => `${GOOGLE_ISSUER}|${subject}`;

const CLAIM_A = "a".repeat(64);
const CLAIM_B = "b".repeat(64);

type T = ReturnType<typeof initConvexTest>;

function asGoogleUser(t: T, subject: string, name: string) {
  return t.withIdentity({
    tokenIdentifier: tokenIdentifier(subject),
    name,
    email: `${subject}@example.com`,
  });
}

describe("anonymous identities", () => {
  it("creates and resolves a profile from a claim", async () => {
    const t = initConvexTest();
    const profileId = await t.mutation(api.example.ensureProfile, {
      anonymousClaim: CLAIM_A,
    });
    const profile = await t.query(api.example.currentProfile, {
      anonymousClaim: CLAIM_A,
    });
    expect(profile?._id).toBe(profileId);
    expect(profile?.isAnonymous).toBe(true);
  });

  it("rejects malformed claims instead of minting identities for them", async () => {
    const t = initConvexTest();
    await expect(
      t.mutation(api.example.ensureProfile, {
        anonymousClaim: "not-a-valid-claim",
      }),
    ).rejects.toThrow("A valid anonymous claim is required");
    await expect(t.mutation(api.example.ensureProfile, {})).rejects.toThrow();
  });

  it("scopes ownership to the claim presented", async () => {
    const t = initConvexTest();
    await t.mutation(api.example.ensureProfile, { anonymousClaim: CLAIM_A });
    await t.mutation(api.example.ensureProfile, { anonymousClaim: CLAIM_B });
    const noteId = await t.mutation(api.example.addNote, {
      text: "mine",
      anonymousClaim: CLAIM_A,
    });

    await expect(
      t.mutation(api.example.removeNote, {
        noteId,
        anonymousClaim: CLAIM_B,
      }),
    ).rejects.toThrow("Unauthorized");
  });

  it("never exposes credentials or identity ids through queries", async () => {
    const t = initConvexTest();
    await t.mutation(api.example.ensureProfile, { anonymousClaim: CLAIM_A });
    const profile = await t.query(api.example.currentProfile, {
      anonymousClaim: CLAIM_A,
    });
    expect(profile).not.toHaveProperty("identityId");
    expect(profile).not.toHaveProperty("email");
    expect(JSON.stringify(profile)).not.toContain(CLAIM_A);
  });
});

describe("anonymous to Google upgrade", () => {
  it("keeps the same profile and retires the claim", async () => {
    const t = initConvexTest();
    const anonProfileId = await t.mutation(api.example.ensureProfile, {
      anonymousClaim: CLAIM_A,
    });
    const noteId = await t.mutation(api.example.addNote, {
      text: "created while anonymous",
      anonymousClaim: CLAIM_A,
    });

    const asAlice = asGoogleUser(t, "alice", "Alice");
    const upgradedId = await asAlice.mutation(api.example.ensureProfile, {
      anonymousClaim: CLAIM_A,
    });

    // In-place upgrade: the profile row (and everything keyed by it)
    // survives untouched.
    expect(upgradedId).toBe(anonProfileId);
    const profile = await asAlice.query(api.example.currentProfile, {});
    expect(profile?.isAnonymous).toBe(false);
    expect(profile?.displayName).toBe("Alice");

    // The retired claim no longer resolves and no longer authorizes.
    expect(
      await t.query(api.example.currentProfile, { anonymousClaim: CLAIM_A }),
    ).toBeNull();
    await expect(
      t.mutation(api.example.removeNote, { noteId, anonymousClaim: CLAIM_A }),
    ).rejects.toThrow("Unauthorized");
  });

  it("does not hand back an upgraded profile for its stale claim", async () => {
    const t = initConvexTest();
    const victimProfileId = await t.mutation(api.example.ensureProfile, {
      anonymousClaim: CLAIM_A,
    });
    await asGoogleUser(t, "victim", "Victim").mutation(
      api.example.ensureProfile,
      { anonymousClaim: CLAIM_A },
    );

    const staleId = await t.mutation(api.example.ensureProfile, {
      anonymousClaim: CLAIM_A,
    });
    expect(staleId).not.toBe(victimProfileId);
  });

  it("refuses to re-point an upgraded account at another Google user", async () => {
    const t = initConvexTest();
    await t.mutation(api.example.ensureProfile, { anonymousClaim: CLAIM_A });
    const victimId = await asGoogleUser(t, "victim", "Victim").mutation(
      api.example.ensureProfile,
      { anonymousClaim: CLAIM_A },
    );
    const victimNote = await asGoogleUser(t, "victim", "Victim").mutation(
      api.example.addNote,
      { text: "victim's note" },
    );

    // The attacker learned the victim's old claim and signs in themselves.
    const asAttacker = asGoogleUser(t, "attacker", "Attacker");
    const attackerId = await asAttacker.mutation(api.example.ensureProfile, {
      anonymousClaim: CLAIM_A,
    });

    expect(attackerId).not.toBe(victimId);
    // The victim keeps their profile and their data.
    const victimProfile = await asGoogleUser(t, "victim", "Victim").query(
      api.example.currentProfile,
      {},
    );
    expect(victimProfile?._id).toBe(victimId);
    expect(victimProfile?.displayName).toBe("Victim");
    await expect(
      asAttacker.mutation(api.example.removeNote, { noteId: victimNote }),
    ).rejects.toThrow("Unauthorized");
  });

  it("absorbs a live anonymous profile into an existing Google account", async () => {
    const t = initConvexTest();
    const asBob = asGoogleUser(t, "bob", "Bob");
    const googleProfileId = await asBob.mutation(api.example.ensureProfile, {});

    // Bob also has an anonymous profile from before signing in.
    await t.mutation(api.example.ensureProfile, { anonymousClaim: CLAIM_B });
    await t.mutation(api.example.addNote, {
      text: "written before signing in",
      anonymousClaim: CLAIM_B,
    });

    const mergedId = await asBob.mutation(api.example.ensureProfile, {
      anonymousClaim: CLAIM_B,
    });
    expect(mergedId).toBe(googleProfileId);

    // The app moved the absorbed profile's data over...
    const notes = await asBob.query(api.example.listMyNotes, {});
    expect(notes.map((note) => note.text)).toContain(
      "written before signing in",
    );
    // ...and the claim is retired.
    expect(
      await t.query(api.example.currentProfile, { anonymousClaim: CLAIM_B }),
    ).toBeNull();
  });
});

describe("google-only mode", () => {
  it("ignores anonymous claims entirely", async () => {
    const t = initConvexTest();
    // Even a claim backing a real anonymous identity resolves to nothing
    // through the google-only instance.
    await t.mutation(api.example.ensureProfile, { anonymousClaim: CLAIM_A });
    expect(
      await t.query(api.example.resolveSsoOnly, { anonymousClaim: CLAIM_A }),
    ).toBeNull();
  });

  it("requires Google sign-in to ensure an identity", async () => {
    const t = initConvexTest();
    await expect(
      t.mutation(api.example.ensureProfileSsoOnly, {
        anonymousClaim: CLAIM_A,
      }),
    ).rejects.toThrow("Google sign-in required");

    const identityId = await asGoogleUser(t, "carol", "Carol").mutation(
      api.example.ensureProfileSsoOnly,
      {},
    );
    expect(identityId).toBeTruthy();
  });

  it("does not merge or retire anonymous identities", async () => {
    const t = initConvexTest();
    await t.mutation(api.example.ensureProfile, { anonymousClaim: CLAIM_A });

    // A Google sign-in through the google-only instance carrying a live
    // claim must leave the anonymous identity untouched.
    await asGoogleUser(t, "dave", "Dave").mutation(
      api.example.ensureProfileSsoOnly,
      { anonymousClaim: CLAIM_A },
    );

    const anonProfile = await t.query(api.example.currentProfile, {
      anonymousClaim: CLAIM_A,
    });
    expect(anonProfile).not.toBeNull();
    expect(anonProfile?.isAnonymous).toBe(true);
  });
});
