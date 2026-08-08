import { mutation, query } from "./_generated/server.js";
import { components } from "./_generated/api.js";
import { v } from "convex/values";
import { GooglyAuth } from "@clammet/convex-googly-auth";
import type { Doc } from "./_generated/dataModel.js";
import type { MutationCtx, QueryCtx } from "./_generated/server.js";

const googly = new GooglyAuth(components.googlyAuth);
// A second instance in Google-only mode, to show (and test) that anonymous
// claims are ignored server-side when an app opts out of them. A real app
// would create exactly one instance.
const googlySso = new GooglyAuth(components.googlyAuth, { anonymous: false });

async function profileByIdentityId(
  ctx: QueryCtx,
  identityId: string,
): Promise<Doc<"profiles"> | null> {
  return await ctx.db
    .query("profiles")
    .withIndex("by_identityId", (q) => q.eq("identityId", identityId))
    .unique();
}

async function currentProfileDoc(
  ctx: QueryCtx,
  anonymousClaim: string | undefined,
): Promise<Doc<"profiles"> | null> {
  const identityId = await googly.resolveIdentity(ctx, { anonymousClaim });
  if (identityId === null) {
    return null;
  }
  return await profileByIdentityId(ctx, identityId);
}

/**
 * When sign-in absorbed a second identity, the app reconciles its own data:
 * here notes are repointed at the surviving profile and the absorbed profile
 * row is deleted. (An app could instead keep an alias table.)
 */
async function absorbProfile(
  ctx: MutationCtx,
  mergedFromId: string,
  targetProfileId: Doc<"profiles">["_id"],
): Promise<void> {
  const absorbed = await profileByIdentityId(ctx, mergedFromId);
  if (absorbed === null) {
    return;
  }
  const notes = ctx.db
    .query("notes")
    .withIndex("by_ownerProfileId", (q) => q.eq("ownerProfileId", absorbed._id));
  for await (const note of notes) {
    await ctx.db.patch("notes", note._id, { ownerProfileId: targetProfileId });
  }
  await ctx.db.delete("profiles", absorbed._id);
}

export const ensureProfile = mutation({
  args: { anonymousClaim: v.optional(v.string()) },
  returns: v.id("profiles"),
  handler: async (ctx, args) => {
    const result = await googly.ensureIdentity(ctx, args);
    const existing = await profileByIdentityId(ctx, result.identityId);
    let profileId: Doc<"profiles">["_id"];
    if (existing === null) {
      profileId = await ctx.db.insert("profiles", {
        identityId: result.identityId,
        displayName: result.identity?.name ?? "Anonymous",
        email: result.identity?.email,
        isAnonymous: result.identity === null,
      });
    } else {
      await ctx.db.patch("profiles", existing._id, {
        displayName: result.identity?.name ?? existing.displayName,
        email: result.identity?.email ?? existing.email,
        isAnonymous: result.identity === null,
      });
      profileId = existing._id;
    }
    if (result.mergedFromId !== null) {
      await absorbProfile(ctx, result.mergedFromId, profileId);
    }
    return profileId;
  },
});

// Only public fields — a profile row is looked up by credentials, so raw
// documents must never be returned to clients.
const publicProfileValidator = v.object({
  _id: v.id("profiles"),
  displayName: v.string(),
  isAnonymous: v.boolean(),
});

export const currentProfile = query({
  args: { anonymousClaim: v.optional(v.string()) },
  returns: v.union(publicProfileValidator, v.null()),
  handler: async (ctx, args) => {
    const profile = await currentProfileDoc(ctx, args.anonymousClaim);
    if (profile === null) {
      return null;
    }
    return {
      _id: profile._id,
      displayName: profile.displayName,
      isAnonymous: profile.isAnonymous,
    };
  },
});

export const addNote = mutation({
  args: { text: v.string(), anonymousClaim: v.optional(v.string()) },
  returns: v.id("notes"),
  handler: async (ctx, args) => {
    const profile = await currentProfileDoc(ctx, args.anonymousClaim);
    if (profile === null) {
      throw new Error("Not authenticated");
    }
    return await ctx.db.insert("notes", {
      ownerProfileId: profile._id,
      text: args.text,
    });
  },
});

export const removeNote = mutation({
  args: { noteId: v.id("notes"), anonymousClaim: v.optional(v.string()) },
  returns: v.null(),
  handler: async (ctx, args) => {
    const profile = await currentProfileDoc(ctx, args.anonymousClaim);
    const note = await ctx.db.get("notes", args.noteId);
    if (note === null) {
      return null;
    }
    if (profile === null || note.ownerProfileId !== profile._id) {
      throw new Error("Unauthorized");
    }
    await ctx.db.delete("notes", args.noteId);
    return null;
  },
});

export const listMyNotes = query({
  args: { anonymousClaim: v.optional(v.string()) },
  returns: v.array(v.object({ _id: v.id("notes"), text: v.string() })),
  handler: async (ctx, args) => {
    const profile = await currentProfileDoc(ctx, args.anonymousClaim);
    if (profile === null) {
      return [];
    }
    const notes = await ctx.db
      .query("notes")
      .withIndex("by_ownerProfileId", (q) =>
        q.eq("ownerProfileId", profile._id),
      )
      .take(100);
    return notes.map((note) => ({ _id: note._id, text: note.text }));
  },
});

// --- Google-only mode (for apps that opt out of anonymous identities) ---

export const ensureProfileSsoOnly = mutation({
  args: { anonymousClaim: v.optional(v.string()) },
  returns: v.string(),
  handler: async (ctx, args) => {
    const result = await googlySso.ensureIdentity(ctx, args);
    return result.identityId;
  },
});

export const resolveSsoOnly = query({
  args: { anonymousClaim: v.optional(v.string()) },
  returns: v.union(v.string(), v.null()),
  handler: async (ctx, args) => {
    return await googlySso.resolveIdentity(ctx, args);
  },
});
