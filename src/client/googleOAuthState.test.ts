import { describe, expect, it } from "vitest";
import {
  createGoogleOAuthState,
  isSafeOAuthRedirect,
  verifyGoogleOAuthState,
} from "./googleOAuthState.js";

const SECRET = "test-secret";
const NS = "googly-auth";
const STATE = {
  nonce: "0123456789abcdef",
  origin: "https://app.example.test",
  redirect: "/somewhere?x=1",
};

describe("google OAuth state", () => {
  it("round-trips a valid state", async () => {
    const serialized = await createGoogleOAuthState(SECRET, NS, STATE);
    expect(await verifyGoogleOAuthState(SECRET, NS, serialized)).toEqual(
      STATE,
    );
  });

  it("rejects tampering with any field", async () => {
    const serialized = await createGoogleOAuthState(SECRET, NS, STATE);
    const tampered = serialized.replace(
      encodeURIComponent(STATE.origin),
      encodeURIComponent("https://evil.example.test"),
    );
    expect(await verifyGoogleOAuthState(SECRET, NS, tampered)).toBeNull();
  });

  it("rejects states signed with a different secret or namespace", async () => {
    const serialized = await createGoogleOAuthState(SECRET, NS, STATE);
    expect(
      await verifyGoogleOAuthState("other-secret", NS, serialized),
    ).toBeNull();
    expect(
      await verifyGoogleOAuthState(SECRET, "other-app", serialized),
    ).toBeNull();
  });

  it("rejects extra or missing parameters", async () => {
    const serialized = await createGoogleOAuthState(SECRET, NS, STATE);
    expect(
      await verifyGoogleOAuthState(SECRET, NS, `${serialized}&extra=1`),
    ).toBeNull();
    expect(await verifyGoogleOAuthState(SECRET, NS, "")).toBeNull();
  });

  it("refuses to sign an invalid state", async () => {
    await expect(
      createGoogleOAuthState(SECRET, NS, {
        ...STATE,
        redirect: "https://evil.example.test/",
      }),
    ).rejects.toThrow();
    await expect(
      createGoogleOAuthState(SECRET, NS, { ...STATE, nonce: "short" }),
    ).rejects.toThrow();
  });

  it("only allows same-site relative redirects", () => {
    expect(isSafeOAuthRedirect("/ok")).toBe(true);
    expect(isSafeOAuthRedirect("//evil.example.test")).toBe(false);
    expect(isSafeOAuthRedirect("https://evil.example.test")).toBe(false);
    expect(isSafeOAuthRedirect("")).toBe(false);
  });
});
