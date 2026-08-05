import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

export default defineSchema({
  // The app owns its profile table; the component only hands out opaque
  // identity ids. Never store credentials here.
  profiles: defineTable({
    identityId: v.string(),
    displayName: v.string(),
    email: v.optional(v.string()),
    isAnonymous: v.boolean(),
  }).index("by_identityId", ["identityId"]),

  notes: defineTable({
    ownerProfileId: v.id("profiles"),
    text: v.string(),
  }).index("by_ownerProfileId", ["ownerProfileId"]),
});
