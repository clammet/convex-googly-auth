/**
 * App-side API for the googlyAuth component.
 *
 * Auth and environment access happen here, in the app's own functions —
 * `ctx.auth` and `process.env` are not available inside the component. The
 * component only stores credentials (Google subjects, anonymous claim
 * hashes, refresh-token sessions) keyed to opaque identity ids; the app owns
 * its profile table and stores `identityId` on it.
 */
import { httpActionGeneric } from "convex/server";
import type {
  Auth,
  GenericActionCtx,
  GenericDataModel,
  GenericMutationCtx,
  GenericQueryCtx,
  HttpRouter,
  UserIdentity,
} from "convex/server";
import type { ComponentApi } from "../component/_generated/component.js";
import {
  bytesToBase64Url,
  base64UrlToBytes,
  hashAnonymousClaim,
  isValidAnonymousClaim,
  DEFAULT_SESSION_ABSOLUTE_TTL_MS,
  DEFAULT_SESSION_IDLE_TTL_MS,
} from "../component/shared.js";
import {
  createGoogleOAuthState,
  isValidGoogleOAuthState,
  verifyGoogleOAuthState,
} from "./googleOAuthState.js";
import type { GoogleOAuthState } from "./googleOAuthState.js";

export {
  isValidAnonymousClaim,
  DEFAULT_SESSION_ABSOLUTE_TTL_MS,
  DEFAULT_SESSION_IDLE_TTL_MS,
};
export type { ComponentApi };

type QueryCtx = Pick<GenericQueryCtx<GenericDataModel>, "runQuery"> & {
  auth: Auth;
};
type MutationCtx = Pick<
  GenericMutationCtx<GenericDataModel>,
  "runQuery" | "runMutation"
> & { auth: Auth };
type ActionCtx = GenericActionCtx<GenericDataModel>;

export interface GooglyAuthOptions {
  /**
   * Whether anonymous identities exist at all. When false, anonymous claims
   * are ignored server-side everywhere: `resolveIdentity` returns null for
   * unauthenticated callers and `ensureIdentity` requires a Google sign-in.
   * Defaults to true.
   */
  anonymous?: boolean;
  /**
   * Sliding idle window: a session ends after this long without a refresh,
   * i.e. without the user opening the app. Defaults to 60 days.
   */
  sessionIdleTtlMs?: number;
  /**
   * Hard cap on a session's lifetime from creation, regardless of activity.
   * Defaults to 180 days — Google refresh tokens expire after ~6 months of
   * disuse anyway, so longer values buy nothing.
   */
  sessionAbsoluteTtlMs?: number;
}

export interface EnsureIdentityResult {
  /** Opaque id the app should key its own profile row by. */
  identityId: string;
  /** The verified Google identity, or null for anonymous callers. */
  identity: UserIdentity | null;
  /** True when a brand-new identity was created. */
  created: boolean;
  /**
   * True when an anonymous identity gained its Google credential in place.
   * The identityId is unchanged, so app data keyed by it needs no migration;
   * the old claim was retired and can never authorize again.
   */
  upgraded: boolean;
  /**
   * Set when the caller already had a Google identity and also presented a
   * live anonymous claim: that anonymous identity was absorbed into
   * `identityId` and its claim retired. The app should move or alias its own
   * rows keyed by this id.
   */
  mergedFromId: string | null;
}

export interface RegisterRoutesOptions {
  /** Route prefix, default "/auth/" (routes: google/start, google/callback, refresh, sign-out). */
  pathPrefix?: string;
  /** Canonical web origin; its origin is always allowed. Default: process.env.SITE_URL. */
  siteUrl?: string;
  /** Default: process.env.AUTH_GOOGLE_ID. */
  googleClientId?: string;
  /** Default: process.env.AUTH_GOOGLE_SECRET. */
  googleClientSecret?: string;
  /** Extra origins (exact `URL.origin` strings) allowed to sign in and refresh. */
  allowedOrigins?: string[];
  /** Dynamic origin check, e.g. against an app table of custom domains. */
  isAllowedOrigin?: (ctx: ActionCtx, origin: string) => Promise<boolean>;
  /**
   * Domain-separation namespace for HMAC signing keys. Changing it (or the
   * Google client secret) invalidates outstanding OAuth states and session
   * tokens. Default "googly-auth".
   */
  signingNamespace?: string;
  /** Also revoke the Google refresh token when a sign-out removes its last session. */
  revokeRefreshTokenOnSignOut?: boolean;
}

const encoder = new TextEncoder();

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function getSessionSigningKey(
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
    encoder.encode(`${namespace}-google-session-signing-v1`),
  );
  return await crypto.subtle.importKey(
    "raw",
    derived,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

async function signSessionToken(
  secret: string,
  namespace: string,
  sessionToken: string,
  googleSubject: string,
): Promise<string> {
  const signature = await crypto.subtle.sign(
    "HMAC",
    await getSessionSigningKey(secret, namespace),
    encoder.encode(`${sessionToken}|${googleSubject}`),
  );
  return `${sessionToken}.${bytesToBase64Url(new Uint8Array(signature))}`;
}

async function verifySessionToken(
  secret: string,
  namespace: string,
  signedToken: string,
  googleSubject: string,
): Promise<string | null> {
  const separator = signedToken.indexOf(".");
  if (separator < 1) {
    return null;
  }
  const sessionToken = signedToken.slice(0, separator);
  const signature = base64UrlToBytes(signedToken.slice(separator + 1));
  if (signature === null) {
    return null;
  }
  const valid = await crypto.subtle.verify(
    "HMAC",
    await getSessionSigningKey(secret, namespace),
    signature.buffer as ArrayBuffer,
    encoder.encode(`${sessionToken}|${googleSubject}`),
  );
  return valid ? sessionToken : null;
}

function decodeJwtPayload(token: string): Record<string, unknown> | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) {
      return null;
    }
    const decoded = base64UrlToBytes(parts[1]);
    if (decoded === null) {
      return null;
    }
    const value: unknown = JSON.parse(new TextDecoder().decode(decoded));
    return isRecord(value) ? value : null;
  } catch {
    return null;
  }
}

function googleSubjectFromToken(
  token: string,
  googleClientId: string,
  expectedNonce?: string,
): string | null {
  const payload = decodeJwtPayload(token);
  if (
    payload === null ||
    payload.aud !== googleClientId ||
    (payload.iss !== "https://accounts.google.com" &&
      payload.iss !== "accounts.google.com") ||
    typeof payload.exp !== "number" ||
    payload.exp * 1000 <= Date.now() ||
    typeof payload.sub !== "string" ||
    payload.sub.length === 0 ||
    (expectedNonce !== undefined && payload.nonce !== expectedNonce)
  ) {
    return null;
  }
  return payload.sub;
}

function authJson(
  value: unknown,
  status: number,
  headers: Record<string, string>,
): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...headers,
    },
  });
}

function normalizePathPrefix(prefix: string): string {
  if (!prefix.startsWith("/")) {
    throw new Error("pathPrefix must start with '/'");
  }
  return prefix.endsWith("/") ? prefix : `${prefix}/`;
}

function oauthCallbackUrl(requestUrl: string, pathPrefix: string): string {
  const request = new URL(requestUrl);
  if (
    (request.protocol !== "http:" && request.protocol !== "https:") ||
    request.username !== "" ||
    request.password !== ""
  ) {
    throw new Error("Invalid OAuth request URL");
  }
  return new URL(`${pathPrefix}google/callback`, request.origin).toString();
}

export class GooglyAuth {
  constructor(
    public component: ComponentApi,
    public options: GooglyAuthOptions = {},
  ) {}

  get anonymousEnabled(): boolean {
    return this.options.anonymous !== false;
  }

  get sessionIdleTtlMs(): number {
    return this.options.sessionIdleTtlMs ?? DEFAULT_SESSION_IDLE_TTL_MS;
  }

  get sessionAbsoluteTtlMs(): number {
    return this.options.sessionAbsoluteTtlMs ?? DEFAULT_SESSION_ABSOLUTE_TTL_MS;
  }

  /**
   * Resolve the caller to an identity id, or null when unauthenticated.
   * A verified Google identity always wins; the anonymous claim is only
   * consulted for unauthenticated callers, and only when anonymous
   * identities are enabled.
   */
  async resolveIdentity(
    ctx: QueryCtx,
    args: { anonymousClaim?: string } = {},
  ): Promise<string | null> {
    const identity = await ctx.auth.getUserIdentity();
    if (identity !== null) {
      return await ctx.runQuery(this.component.lib.resolve, {
        googleSubject: identity.tokenIdentifier,
      });
    }
    if (!this.anonymousEnabled) {
      return null;
    }
    const claimHash = await hashAnonymousClaim(args.anonymousClaim);
    if (claimHash === null) {
      return null;
    }
    return await ctx.runQuery(this.component.lib.resolve, { claimHash });
  }

  /**
   * Find-or-create the caller's identity. Call from the app's own
   * profile-bootstrap mutation, then create/update the app profile row
   * keyed by the returned `identityId` (see EnsureIdentityResult for the
   * upgrade and merge signals).
   */
  async ensureIdentity(
    ctx: MutationCtx,
    args: { anonymousClaim?: string } = {},
  ): Promise<EnsureIdentityResult> {
    const identity = await ctx.auth.getUserIdentity();
    const claimHash = this.anonymousEnabled
      ? await hashAnonymousClaim(args.anonymousClaim)
      : null;
    if (identity === null) {
      if (!this.anonymousEnabled) {
        throw new Error("Google sign-in required");
      }
      if (claimHash === null) {
        throw new Error("A valid anonymous claim is required");
      }
      const result = await ctx.runMutation(this.component.lib.ensure, {
        claimHash,
        now: Date.now(),
      });
      return { ...result, identity: null };
    }
    const result = await ctx.runMutation(this.component.lib.ensure, {
      googleSubject: identity.tokenIdentifier,
      claimHash: claimHash ?? undefined,
      now: Date.now(),
    });
    return { ...result, identity };
  }

  /** Delete sessions past their absolute deadline. Call from an app cron. */
  async cleanupExpiredSessions(
    ctx: Pick<GenericMutationCtx<GenericDataModel>, "runMutation">,
  ): Promise<number> {
    return await ctx.runMutation(this.component.lib.cleanupExpiredSessions, {
      now: Date.now(),
    });
  }

  /**
   * Mount the Google OAuth + session routes on the app's http router:
   *
   * - GET  {prefix}google/start     – begin the OAuth code flow
   * - GET  {prefix}google/callback  – token exchange; redirects to
   *   `{origin}/auth/callback` with token/session/state in the URL fragment
   * - POST {prefix}refresh          – exchange a signed session token for a
   *   fresh Google ID token
   * - POST {prefix}sign-out         – revoke a session
   */
  registerRoutes(http: HttpRouter, opts: RegisterRoutesOptions = {}): void {
    const component = this.component;
    const pathPrefix = normalizePathPrefix(opts.pathPrefix ?? "/auth/");
    const namespace = opts.signingNamespace ?? "googly-auth";
    const idleTtlMs = this.sessionIdleTtlMs;
    const absoluteTtlMs = this.sessionAbsoluteTtlMs;

    const config = () => {
      const googleClientId = opts.googleClientId ?? process.env.AUTH_GOOGLE_ID;
      const googleClientSecret =
        opts.googleClientSecret ?? process.env.AUTH_GOOGLE_SECRET;
      if (!googleClientId || !googleClientSecret) {
        throw new Error(
          "AUTH_GOOGLE_ID and AUTH_GOOGLE_SECRET must be set (or passed to registerRoutes)",
        );
      }
      return {
        googleClientId,
        googleClientSecret,
        siteUrl: opts.siteUrl ?? process.env.SITE_URL,
      };
    };

    const originAllowed = async (
      ctx: ActionCtx,
      origin: string,
    ): Promise<boolean> => {
      let requested: URL;
      try {
        requested = new URL(origin);
      } catch {
        return false;
      }
      if (requested.origin !== origin || requested.origin === "null") {
        return false;
      }
      const { siteUrl } = config();
      if (siteUrl !== undefined) {
        try {
          if (new URL(siteUrl).origin === requested.origin) {
            return true;
          }
        } catch {
          // fall through to the other checks
        }
      }
      const isLocalDevelopment =
        requested.protocol === "http:" && requested.hostname === "localhost";
      if (requested.protocol !== "https:" && !isLocalDevelopment) {
        return false;
      }
      if (opts.allowedOrigins?.includes(requested.origin)) {
        return true;
      }
      if (opts.isAllowedOrigin !== undefined) {
        return await opts.isAllowedOrigin(ctx, requested.origin);
      }
      return false;
    };

    const corsHeaders = async (
      ctx: ActionCtx,
      request: Request,
    ): Promise<Record<string, string> | null> => {
      const origin = request.headers.get("origin");
      if (origin === null || !(await originAllowed(ctx, origin))) {
        return null;
      }
      return {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Methods": "POST",
        "Access-Control-Allow-Headers": "Content-Type",
        Vary: "Origin",
      };
    };

    const googleAuthorizationRedirect = async (
      requestUrl: string,
      googleClientId: string,
      googleClientSecret: string,
      state: GoogleOAuthState,
      prompt: "select_account" | "consent",
    ): Promise<Response> => {
      const authorizationUrl = new URL(
        "https://accounts.google.com/o/oauth2/v2/auth",
      );
      authorizationUrl.searchParams.set("client_id", googleClientId);
      authorizationUrl.searchParams.set(
        "redirect_uri",
        oauthCallbackUrl(requestUrl, pathPrefix),
      );
      authorizationUrl.searchParams.set("response_type", "code");
      authorizationUrl.searchParams.set("scope", "openid profile email");
      authorizationUrl.searchParams.set(
        "state",
        await createGoogleOAuthState(googleClientSecret, namespace, state),
      );
      authorizationUrl.searchParams.set("nonce", state.nonce);
      authorizationUrl.searchParams.set("access_type", "offline");
      authorizationUrl.searchParams.set("prompt", prompt);
      return new Response(null, {
        status: 302,
        headers: { Location: authorizationUrl.toString() },
      });
    };

    http.route({
      path: `${pathPrefix}google/start`,
      method: "GET",
      handler: httpActionGeneric(async (ctx, request) => {
        const { googleClientId, googleClientSecret } = config();
        const url = new URL(request.url);
        const stateInput = {
          nonce: url.searchParams.get("nonce") ?? "",
          origin: url.searchParams.get("origin") ?? "",
          redirect: url.searchParams.get("redirect") ?? "",
        };
        if (!isValidGoogleOAuthState(stateInput)) {
          return new Response("Invalid OAuth request", { status: 400 });
        }
        if (!(await originAllowed(ctx, stateInput.origin))) {
          return new Response("OAuth return origin is not configured", {
            status: 403,
          });
        }

        // select_account keeps returning users to a fast account-picker
        // bounce. The callback re-runs the flow with prompt=consent only
        // when a refresh token is needed and none is stored.
        return await googleAuthorizationRedirect(
          request.url,
          googleClientId,
          googleClientSecret,
          stateInput,
          "select_account",
        );
      }),
    });

    http.route({
      path: `${pathPrefix}google/callback`,
      method: "GET",
      handler: httpActionGeneric(async (ctx, request) => {
        const { googleClientId, googleClientSecret } = config();
        const url = new URL(request.url);
        const state = url.searchParams.get("state") ?? "";
        const verifiedState = await verifyGoogleOAuthState(
          googleClientSecret,
          namespace,
          state,
        );
        if (
          verifiedState === null ||
          !(await originAllowed(ctx, verifiedState.origin))
        ) {
          return new Response("Invalid or expired OAuth state", {
            status: 400,
          });
        }
        const destination = new URL("/auth/callback", verifiedState.origin);
        const oauthError = url.searchParams.get("error");
        if (oauthError !== null) {
          destination.hash = new URLSearchParams({
            error: oauthError,
            state,
          }).toString();
          return new Response(null, {
            status: 302,
            headers: { Location: destination.toString() },
          });
        }
        const code = url.searchParams.get("code");
        if (code === null) {
          return new Response("Missing authorization code", { status: 400 });
        }
        const tokenResponse = await fetch(
          "https://oauth2.googleapis.com/token",
          {
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
              code,
              client_id: googleClientId,
              client_secret: googleClientSecret,
              redirect_uri: oauthCallbackUrl(request.url, pathPrefix),
              grant_type: "authorization_code",
            }),
          },
        );
        if (!tokenResponse.ok) {
          console.error("Google token exchange failed", tokenResponse.status);
          return new Response("Authentication failed", { status: 502 });
        }
        const tokenValue: unknown = await tokenResponse.json();
        if (!isRecord(tokenValue) || typeof tokenValue.id_token !== "string") {
          return new Response("Google did not return an ID token", {
            status: 502,
          });
        }
        const googleSubject = googleSubjectFromToken(
          tokenValue.id_token,
          googleClientId,
          verifiedState.nonce,
        );
        if (googleSubject === null) {
          return new Response("Google returned an invalid ID token", {
            status: 502,
          });
        }
        const now = Date.now();
        let refreshToken =
          typeof tokenValue.refresh_token === "string"
            ? tokenValue.refresh_token
            : null;
        if (refreshToken === null) {
          const existing = await ctx.runQuery(
            component.lib.latestRefreshTokenForSubject,
            { googleSubject, now, idleTtlMs },
          );
          refreshToken = existing?.refreshToken ?? null;
        }
        if (refreshToken === null && verifiedState.consented !== true) {
          // Google only hands out a refresh token on a consent prompt. No
          // token came back and none is stored, so bounce through Google once
          // more with prompt=consent; the flag in the re-signed state stops
          // this from looping if Google still withholds one.
          return await googleAuthorizationRedirect(
            request.url,
            googleClientId,
            googleClientSecret,
            { ...verifiedState, consented: true },
            "consent",
          );
        }
        const fragment = new URLSearchParams({
          token: tokenValue.id_token,
          state,
        });
        if (refreshToken !== null) {
          const sessionToken = crypto.randomUUID();
          await ctx.runMutation(component.lib.createSession, {
            sessionToken,
            refreshToken,
            googleSubject,
            now,
            absoluteTtlMs,
          });
          fragment.set(
            "session",
            await signSessionToken(
              googleClientSecret,
              namespace,
              sessionToken,
              googleSubject,
            ),
          );
        }
        destination.hash = fragment.toString();
        return new Response(null, {
          status: 302,
          headers: { Location: destination.toString() },
        });
      }),
    });

    http.route({
      path: `${pathPrefix}refresh`,
      method: "POST",
      handler: httpActionGeneric(async (ctx, request) => {
        const { googleClientId, googleClientSecret } = config();
        const headers = await corsHeaders(ctx, request);
        if (headers === null) {
          return authJson({ error: "Origin not allowed" }, 403, {});
        }
        const body: unknown = await request.json();
        if (!isRecord(body) || typeof body.sessionToken !== "string") {
          return authJson({ error: "Missing session token" }, 400, headers);
        }
        const separator = body.sessionToken.indexOf(".");
        if (separator < 1) {
          return authJson({ error: "Invalid session" }, 401, headers);
        }
        const unsignedToken = body.sessionToken.slice(0, separator);
        const now = Date.now();
        const session = await ctx.runQuery(component.lib.getActiveSession, {
          sessionToken: unsignedToken,
          now,
          idleTtlMs,
        });
        if (
          session === null ||
          (await verifySessionToken(
            googleClientSecret,
            namespace,
            body.sessionToken,
            session.googleSubject,
          )) === null
        ) {
          return authJson({ error: "Invalid session" }, 401, headers);
        }
        const tokenResponse = await fetch(
          "https://oauth2.googleapis.com/token",
          {
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
              client_id: googleClientId,
              client_secret: googleClientSecret,
              refresh_token: session.refreshToken,
              grant_type: "refresh_token",
            }),
          },
        );
        if (!tokenResponse.ok) {
          await ctx.runMutation(component.lib.removeSession, {
            sessionToken: unsignedToken,
            now,
          });
          return authJson({ error: "Refresh failed" }, 401, headers);
        }
        const tokenValue: unknown = await tokenResponse.json();
        if (
          !isRecord(tokenValue) ||
          typeof tokenValue.id_token !== "string" ||
          googleSubjectFromToken(tokenValue.id_token, googleClientId) !==
            session.googleSubject
        ) {
          return authJson(
            { error: "Google returned an invalid ID token" },
            502,
            headers,
          );
        }
        // Rotate the session token on every refresh so an exfiltrated token
        // goes stale on the holder's next refresh instead of living out the
        // session's full TTL.
        const rotated = await ctx.runMutation(component.lib.rotateSession, {
          sessionToken: unsignedToken,
          newSessionToken: crypto.randomUUID(),
          now,
          idleTtlMs,
        });
        if (rotated === null) {
          return authJson({ error: "Invalid session" }, 401, headers);
        }
        return authJson(
          {
            idToken: tokenValue.id_token,
            sessionToken: await signSessionToken(
              googleClientSecret,
              namespace,
              rotated.sessionToken,
              session.googleSubject,
            ),
          },
          200,
          headers,
        );
      }),
    });

    http.route({
      path: `${pathPrefix}sign-out`,
      method: "POST",
      handler: httpActionGeneric(async (ctx, request) => {
        const { googleClientId, googleClientSecret } = config();
        void googleClientId;
        const headers = await corsHeaders(ctx, request);
        if (headers === null) {
          return new Response(null, { status: 403 });
        }
        const body: unknown = await request.json();
        if (!isRecord(body) || typeof body.sessionToken !== "string") {
          return new Response(null, { status: 204, headers });
        }
        const separator = body.sessionToken.indexOf(".");
        if (separator > 0) {
          const unsignedToken = body.sessionToken.slice(0, separator);
          const now = Date.now();
          const session = await ctx.runQuery(component.lib.getActiveSession, {
            sessionToken: unsignedToken,
            now,
            idleTtlMs,
          });
          if (
            session !== null &&
            (await verifySessionToken(
              googleClientSecret,
              namespace,
              body.sessionToken,
              session.googleSubject,
            )) !== null
          ) {
            const removed = await ctx.runMutation(component.lib.removeSession, {
              sessionToken: unsignedToken,
              now,
            });
            if (
              opts.revokeRefreshTokenOnSignOut === true &&
              removed !== null
            ) {
              await fetch("https://oauth2.googleapis.com/revoke", {
                method: "POST",
                headers: {
                  "content-type": "application/x-www-form-urlencoded",
                },
                body: new URLSearchParams({ token: removed.refreshToken }),
              }).catch(() => undefined);
            }
          }
        }
        return new Response(null, { status: 204, headers });
      }),
    });

    for (const path of [`${pathPrefix}refresh`, `${pathPrefix}sign-out`]) {
      http.route({
        path,
        method: "OPTIONS",
        handler: httpActionGeneric(async (ctx, request) => {
          const headers = await corsHeaders(ctx, request);
          return new Response(null, {
            status: headers === null ? 403 : 204,
            headers: headers ?? {},
          });
        }),
      });
    }
  }
}
