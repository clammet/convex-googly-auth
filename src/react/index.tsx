"use client";

/**
 * Browser client for googly-auth.
 *
 * Google issues the ID token and Convex verifies its signature, issuer, and
 * audience from the app's `convex/auth.config.ts`. The browser performs an
 * additional claim check before storing a token, but that is
 * defense-in-depth only.
 *
 * Google refresh tokens stay server-side in the component's table. The
 * browser only holds a signed, opaque session token and exchanges it for
 * fresh short-lived ID tokens through the refresh route.
 *
 * Anonymous users (when enabled) are identified by a 256-bit hex claim in a
 * cookie. It is a bearer secret: the server stores only its hash, and it is
 * retired permanently when the account is upgraded to Google sign-in.
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import type { ReactNode } from "react";
import {
  ANONYMOUS_CLAIM_PATTERN,
  isValidAnonymousClaim,
} from "../component/shared.js";

export interface GooglyAuthClientConfig {
  /** The Convex deployment's HTTP actions URL (e.g. VITE_CONVEX_SITE_URL). */
  convexSiteUrl: string;
  googleClientId: string;
  /**
   * Whether anonymous identities are enabled for this app. When false,
   * the anonymous-claim helpers return null and never set a cookie.
   * Must match the server-side `GooglyAuth` options. Defaults to true.
   */
  anonymous?: boolean;
  /** Prefix for localStorage keys and the claim cookie. Default "googly_auth". */
  storagePrefix?: string;
  /** Must match `registerRoutes`' pathPrefix. Default "/auth/". */
  authPathPrefix?: string;
}

interface GoogleAuthContextValue {
  isLoading: boolean;
  isAuthenticated: boolean;
  token: string | null;
  signIn: (redirectTo?: string) => void;
  signOut: () => void;
  refreshAuth: () => Promise<string | null>;
}

export interface AuthCallbackResult {
  /** Where the app should navigate now (relative URL). */
  redirect: string;
  /** Set when sign-in failed; storage was left untouched. */
  error: string | null;
}

function decodeBase64Url(value: string): string {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
  return atob(padded);
}

function decodeJwtPart(part: string): Record<string, unknown> {
  const value: unknown = JSON.parse(decodeBase64Url(part));
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("Invalid JWT part");
  }
  return value as Record<string, unknown>;
}

function currentRelativeUrl(): string {
  return `${window.location.pathname}${window.location.search}${window.location.hash}`;
}

export function safeRelativeUrl(value: string | undefined): string {
  if (
    value === undefined ||
    !value.startsWith("/") ||
    value.startsWith("//") ||
    value.length > 2_048
  ) {
    return "/";
  }
  return value;
}

function randomClaim(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}

export function createGooglyAuthClient(config: GooglyAuthClientConfig) {
  const convexSiteUrl = config.convexSiteUrl.replace(/\/+$/, "");
  const googleClientId = config.googleClientId;
  const anonymousEnabled = config.anonymous !== false;
  const prefix = config.storagePrefix ?? "googly_auth";
  const authPathPrefix = config.authPathPrefix ?? "/auth/";
  if (!convexSiteUrl || !googleClientId) {
    throw new Error("convexSiteUrl and googleClientId are required");
  }

  const TOKEN_KEY = `${prefix}_google_token`;
  const SESSION_KEY = `${prefix}_google_session`;
  const OAUTH_NONCE_KEY = `${prefix}_oauth_nonce`;
  const CLAIM_COOKIE = `${prefix}_anonymous_claim`;

  function validateGoogleJwt(token: string): boolean {
    try {
      const parts = token.split(".");
      if (parts.length !== 3) return false;
      const header = decodeJwtPart(parts[0]);
      const payload = decodeJwtPart(parts[1]);
      if (header.alg !== "RS256") return false;
      if (
        payload.iss !== "https://accounts.google.com" &&
        payload.iss !== "accounts.google.com"
      ) {
        return false;
      }
      if (payload.aud !== googleClientId) return false;
      if (
        typeof payload.exp !== "number" ||
        payload.exp * 1000 <= Date.now() + 30_000
      ) {
        return false;
      }
      return typeof payload.sub === "string" && payload.sub.length > 0;
    } catch {
      return false;
    }
  }

  /**
   * Read the anonymous claim, minting and storing one if absent. Returns
   * null when anonymous identities are disabled for this app.
   */
  function getOrCreateAnonymousClaim(): string | null {
    if (!anonymousEnabled) {
      return null;
    }
    const existing = document.cookie
      .split(";")
      .map((part) => part.trim())
      .find((part) => part.startsWith(`${CLAIM_COOKIE}=`))
      ?.slice(CLAIM_COOKIE.length + 1);
    if (existing && ANONYMOUS_CLAIM_PATTERN.test(existing)) {
      return existing;
    }
    const claim = randomClaim();
    const secure = window.location.protocol === "https:" ? "; Secure" : "";
    document.cookie = `${CLAIM_COOKIE}=${claim}; Path=/; Max-Age=31536000; SameSite=Lax${secure}`;
    return claim;
  }

  function clearAnonymousClaim(): void {
    document.cookie = `${CLAIM_COOKIE}=; Path=/; Max-Age=0; SameSite=Lax`;
  }

  let refreshPromise: Promise<string | null> | null = null;

  async function refreshIdToken(): Promise<string | null> {
    if (refreshPromise !== null) return refreshPromise;
    refreshPromise = (async () => {
      try {
        const sessionToken = localStorage.getItem(SESSION_KEY);
        if (sessionToken === null) return null;
        const response = await fetch(
          `${convexSiteUrl}${authPathPrefix}refresh`,
          {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ sessionToken }),
          },
        );
        if (response.status === 401) {
          localStorage.removeItem(SESSION_KEY);
          localStorage.removeItem(TOKEN_KEY);
          return null;
        }
        if (!response.ok) return null;
        const value: unknown = await response.json();
        if (
          typeof value === "object" &&
          value !== null &&
          "idToken" in value &&
          typeof value.idToken === "string" &&
          validateGoogleJwt(value.idToken)
        ) {
          // The refresh route rotates the session token; store the
          // replacement or the retired one dies after its grace window.
          if (
            "sessionToken" in value &&
            typeof value.sessionToken === "string"
          ) {
            localStorage.setItem(SESSION_KEY, value.sessionToken);
          }
          localStorage.setItem(TOKEN_KEY, value.idToken);
          return value.idToken;
        }
        return null;
      } catch {
        return null;
      } finally {
        refreshPromise = null;
      }
    })();
    return refreshPromise;
  }

  const GoogleAuthContext = createContext<GoogleAuthContextValue>({
    isLoading: true,
    isAuthenticated: false,
    token: null,
    signIn: () => undefined,
    signOut: () => undefined,
    refreshAuth: async () => null,
  });

  function GoogleAuthProvider(props: { children: ReactNode }) {
    const [token, setToken] = useState<string | null>(() => {
      const stored = localStorage.getItem(TOKEN_KEY);
      if (stored !== null && validateGoogleJwt(stored)) return stored;
      if (stored !== null) localStorage.removeItem(TOKEN_KEY);
      return null;
    });
    const [isLoading, setIsLoading] = useState(() => {
      const stored = localStorage.getItem(TOKEN_KEY);
      const hasValidToken = stored !== null && validateGoogleJwt(stored);
      return !hasValidToken && localStorage.getItem(SESSION_KEY) !== null;
    });

    useEffect(() => {
      if (token !== null || localStorage.getItem(SESSION_KEY) === null) return;
      void refreshIdToken().then((newToken) => {
        if (newToken !== null) setToken(newToken);
        setIsLoading(false);
      });
    }, [token]);

    useEffect(() => {
      if (token === null || localStorage.getItem(SESSION_KEY) === null) return;
      try {
        const payload = decodeJwtPart(token.split(".")[1]);
        if (typeof payload.exp !== "number") return;
        const refreshIn = payload.exp * 1000 - Date.now() - 5 * 60 * 1000;
        if (refreshIn <= 0) {
          void refreshIdToken().then((newToken) => {
            if (newToken !== null) setToken(newToken);
          });
          return;
        }
        const timeout = window.setTimeout(() => {
          void refreshIdToken().then((newToken) => {
            if (newToken !== null) setToken(newToken);
          });
        }, refreshIn);
        return () => window.clearTimeout(timeout);
      } catch {
        return;
      }
    }, [token]);

    const refreshAuth = useCallback(async () => {
      const refreshed = await refreshIdToken();
      if (refreshed !== null) setToken(refreshed);
      return refreshed;
    }, []);

    const signIn = useCallback((redirectTo?: string) => {
      const nonce = crypto.randomUUID();
      sessionStorage.setItem(OAUTH_NONCE_KEY, nonce);
      const startUrl = new URL(
        `${authPathPrefix}google/start`,
        `${convexSiteUrl}/`,
      );
      startUrl.searchParams.set("nonce", nonce);
      startUrl.searchParams.set("origin", window.location.origin);
      startUrl.searchParams.set(
        "redirect",
        safeRelativeUrl(redirectTo ?? currentRelativeUrl()),
      );
      window.location.assign(startUrl.toString());
    }, []);

    const signOut = useCallback(() => {
      const sessionToken = localStorage.getItem(SESSION_KEY);
      localStorage.removeItem(TOKEN_KEY);
      localStorage.removeItem(SESSION_KEY);
      setToken(null);
      setIsLoading(false);
      if (sessionToken !== null) {
        void fetch(`${convexSiteUrl}${authPathPrefix}sign-out`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ sessionToken }),
        }).catch(() => undefined);
      }
    }, []);

    const value = useMemo<GoogleAuthContextValue>(
      () => ({
        isLoading,
        isAuthenticated: token !== null,
        token,
        signIn,
        signOut,
        refreshAuth,
      }),
      [isLoading, refreshAuth, signIn, signOut, token],
    );
    return (
      <GoogleAuthContext.Provider value={value}>
        {props.children}
      </GoogleAuthContext.Provider>
    );
  }

  function useGoogleAuth() {
    return useContext(GoogleAuthContext);
  }

  /** Adapter for `<ConvexProviderWithAuth useAuth={...}>`. */
  function useConvexGooglyAuth() {
    const { isLoading, isAuthenticated, token, refreshAuth } = useGoogleAuth();
    const tokenRef = useRef(token);
    tokenRef.current = token;
    const fetchAccessToken = useCallback(
      async ({ forceRefreshToken }: { forceRefreshToken: boolean }) => {
        const current = tokenRef.current;
        if (
          current !== null &&
          validateGoogleJwt(current) &&
          !forceRefreshToken
        ) {
          return current;
        }
        const refreshed = await refreshAuth();
        if (refreshed !== null) return refreshed;
        const fallback = tokenRef.current;
        return fallback !== null && validateGoogleJwt(fallback)
          ? fallback
          : null;
      },
      [refreshAuth],
    );
    return useMemo(
      () => ({ isLoading, isAuthenticated, fetchAccessToken }),
      [fetchAccessToken, isAuthenticated, isLoading],
    );
  }

  /**
   * The anonymous claim to pass to Convex functions, or null when anonymous
   * identities are disabled (or the caller just signed in and cleared it).
   */
  function useAnonymousClaim(): string | null {
    return anonymousEnabled ? getOrCreateAnonymousClaim() : null;
  }

  /**
   * Process the OAuth redirect landing on `/auth/callback`. Verifies the
   * nonce and origin, stores the credentials, and returns where to navigate.
   * Call exactly once from the app's callback page, then navigate to
   * `result.redirect` (e.g. `window.location.replace(...)`).
   */
  function handleAuthCallback(): AuthCallbackResult {
    const fragment = new URLSearchParams(window.location.hash.slice(1));
    const token = fragment.get("token");
    const sessionToken = fragment.get("session");
    const oauthError = fragment.get("error");
    const state = new URLSearchParams(fragment.get("state") ?? "");
    const nonce = state.get("nonce");
    const origin = state.get("origin");
    const redirect = safeRelativeUrl(state.get("redirect") ?? undefined);
    const storedNonce = sessionStorage.getItem(OAUTH_NONCE_KEY);
    sessionStorage.removeItem(OAUTH_NONCE_KEY);

    if (
      storedNonce === null ||
      nonce !== storedNonce ||
      origin !== window.location.origin
    ) {
      return { redirect: "/", error: "OAuth state verification failed" };
    }
    if (oauthError !== null) {
      return { redirect, error: oauthError };
    }
    if (token === null || !validateGoogleJwt(token)) {
      return { redirect: "/", error: "Google ID token failed validation" };
    }
    localStorage.setItem(TOKEN_KEY, token);
    if (sessionToken !== null) {
      localStorage.setItem(SESSION_KEY, sessionToken);
    }
    return { redirect, error: null };
  }

  return {
    anonymousEnabled,
    validateGoogleJwt,
    getOrCreateAnonymousClaim,
    clearAnonymousClaim,
    useAnonymousClaim,
    GoogleAuthProvider,
    useGoogleAuth,
    useConvexGooglyAuth,
    handleAuthCallback,
    storageKeys: {
      token: TOKEN_KEY,
      session: SESSION_KEY,
      oauthNonce: OAUTH_NONCE_KEY,
      claimCookie: CLAIM_COOKIE,
    },
  };
}

export { isValidAnonymousClaim };
