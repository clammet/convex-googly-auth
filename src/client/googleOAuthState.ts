import { base64UrlToBytes, bytesToBase64Url } from "../component/shared.js";

const encoder = new TextEncoder();
const MAX_STATE_LENGTH = 4_096;
const MAX_ORIGIN_LENGTH = 512;
const MAX_REDIRECT_LENGTH = 2_048;
const NONCE_PATTERN = /^[A-Za-z0-9._~-]{16,128}$/;

export interface GoogleOAuthState {
  nonce: string;
  origin: string;
  redirect: string;
  /**
   * Set server-side when the callback has already bounced the user back
   * through Google with `prompt=consent` to obtain a refresh token. Stops
   * the callback from retrying more than once.
   */
  consented?: boolean;
}

function isCanonicalOrigin(value: string): boolean {
  if (value.length === 0 || value.length > MAX_ORIGIN_LENGTH) {
    return false;
  }
  try {
    const url = new URL(value);
    return (
      url.origin === value &&
      url.origin !== "null" &&
      (url.protocol === "http:" || url.protocol === "https:")
    );
  } catch {
    return false;
  }
}

export function isSafeOAuthRedirect(value: string): boolean {
  return (
    value.length > 0 &&
    value.length <= MAX_REDIRECT_LENGTH &&
    value.startsWith("/") &&
    !value.startsWith("//")
  );
}

export function isValidGoogleOAuthState(state: GoogleOAuthState): boolean {
  return (
    NONCE_PATTERN.test(state.nonce) &&
    isCanonicalOrigin(state.origin) &&
    isSafeOAuthRedirect(state.redirect)
  );
}

function serializeUnsignedState(state: GoogleOAuthState): string {
  const params = new URLSearchParams({
    nonce: state.nonce,
    origin: state.origin,
    redirect: state.redirect,
  });
  if (state.consented === true) {
    params.set("consented", "1");
  }
  return params.toString();
}

async function getStateSigningKey(
  secret: string,
  namespace: string,
): Promise<CryptoKey> {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const derived = await crypto.subtle.sign(
    "HMAC",
    baseKey,
    encoder.encode(`${namespace}-google-oauth-state-v1`),
  );
  return await crypto.subtle.importKey(
    "raw",
    derived,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

export async function createGoogleOAuthState(
  secret: string,
  namespace: string,
  state: GoogleOAuthState,
): Promise<string> {
  if (!isValidGoogleOAuthState(state)) {
    throw new Error("Invalid Google OAuth state");
  }
  const unsigned = serializeUnsignedState(state);
  const signature = await crypto.subtle.sign(
    "HMAC",
    await getStateSigningKey(secret, namespace),
    encoder.encode(unsigned),
  );
  return `${unsigned}&signature=${encodeURIComponent(
    bytesToBase64Url(new Uint8Array(signature)),
  )}`;
}

export async function verifyGoogleOAuthState(
  secret: string,
  namespace: string,
  serialized: string,
): Promise<GoogleOAuthState | null> {
  if (serialized.length === 0 || serialized.length > MAX_STATE_LENGTH) {
    return null;
  }
  const params = new URLSearchParams(serialized);
  const entries = [...params.entries()];
  const allowed = ["nonce", "origin", "redirect", "signature", "consented"];
  const seen = new Set<string>();
  for (const [name] of entries) {
    if (!allowed.includes(name) || seen.has(name)) {
      return null;
    }
    seen.add(name);
  }
  const nonce = params.get("nonce");
  const origin = params.get("origin");
  const redirect = params.get("redirect");
  const encodedSignature = params.get("signature");
  const consented = params.get("consented");
  if (
    nonce === null ||
    origin === null ||
    redirect === null ||
    encodedSignature === null ||
    (consented !== null && consented !== "1")
  ) {
    return null;
  }
  const state: GoogleOAuthState =
    consented === "1"
      ? { nonce, origin, redirect, consented: true }
      : { nonce, origin, redirect };
  if (!isValidGoogleOAuthState(state)) {
    return null;
  }
  const signature = base64UrlToBytes(encodedSignature);
  if (signature === null) {
    return null;
  }
  const valid = await crypto.subtle.verify(
    "HMAC",
    await getStateSigningKey(secret, namespace),
    signature.buffer as ArrayBuffer,
    encoder.encode(serializeUnsignedState(state)),
  );
  return valid ? state : null;
}
