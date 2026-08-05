import { createGooglyAuthClient } from "convex-googly-auth/react";

export const authClient = createGooglyAuthClient({
  convexSiteUrl:
    import.meta.env.VITE_CONVEX_SITE_URL ?? "http://localhost:3211",
  googleClientId:
    import.meta.env.VITE_GOOGLE_CLIENT_ID ??
    "test-client-id.apps.googleusercontent.com",
  storagePrefix: "googly_example",
  // Set `anonymous: false` here (and in convex/example.ts) for a
  // Google-only app.
});
