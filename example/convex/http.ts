import { httpRouter } from "convex/server";
import { components } from "./_generated/api.js";
import { GooglyAuth } from "@clammet/convex-googly-auth";

const http = httpRouter();

const googly = new GooglyAuth(components.googlyAuth);
googly.registerRoutes(http, {
  // Falls back to process.env.SITE_URL / AUTH_GOOGLE_ID / AUTH_GOOGLE_SECRET
  // when omitted; explicit values here keep the example's tests hermetic.
  siteUrl: process.env.SITE_URL ?? "https://app.example.test",
  googleClientId:
    process.env.AUTH_GOOGLE_ID ?? "test-client-id.apps.googleusercontent.com",
  googleClientSecret: process.env.AUTH_GOOGLE_SECRET ?? "test-google-secret",
  allowedOrigins: ["https://alt.example.test"],
});

export default http;
