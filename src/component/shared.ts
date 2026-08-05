/**
 * Constants and pure helpers shared by the component, the app-side client,
 * and the React client. This file must stay free of `_generated` imports so
 * every entry point can use it.
 */

/**
 * A session dies this long after it was created, even while in active use.
 * Google refresh tokens expire after ~6 months of disuse anyway, so a longer
 * absolute lifetime buys nothing.
 */
export const DEFAULT_SESSION_ABSOLUTE_TTL_MS = 180 * 24 * 60 * 60 * 1000;
/** A session dies after this long without a refresh. */
export const DEFAULT_SESSION_IDLE_TTL_MS = 60 * 24 * 60 * 60 * 1000;
/**
 * After a refresh rotates the session token, the retired token stays valid
 * this long so a concurrent refresh from another tab (which read the old
 * token from localStorage just before the rotation landed) is not signed out.
 */
export const SESSION_ROTATION_GRACE_MS = 60 * 1000;

/**
 * Anonymous claims are 256-bit hex bearer secrets generated client-side.
 * Only their SHA-256 hash is ever stored server-side.
 */
export const ANONYMOUS_CLAIM_PATTERN = /^[a-f0-9]{64}$/;

export function isValidAnonymousClaim(
  value: string | undefined,
): value is string {
  return value !== undefined && ANONYMOUS_CLAIM_PATTERN.test(value);
}

export interface SessionLifetime {
  expiresAt: number;
  lastUsedAt: number;
}

export function isSessionExpired(
  session: SessionLifetime,
  now: number,
  idleTtlMs: number = DEFAULT_SESSION_IDLE_TTL_MS,
): boolean {
  return (
    now >= session.expiresAt || now >= session.lastUsedAt + idleTtlMs
  );
}

const textEncoder = new TextEncoder();

export function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

export function base64UrlToBytes(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    return null;
  }
  try {
    const base64 = value.replaceAll("-", "+").replaceAll("_", "/");
    const binary = atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, "="));
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    return null;
  }
}

export async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    textEncoder.encode(value),
  );
  return bytesToBase64Url(new Uint8Array(digest));
}

/**
 * Hash an anonymous claim for storage/lookup. Returns null when the claim is
 * missing or malformed, so callers cannot forget the format check.
 */
export async function hashAnonymousClaim(
  claim: string | undefined,
): Promise<string | null> {
  if (!isValidAnonymousClaim(claim)) {
    return null;
  }
  return await sha256(claim);
}
