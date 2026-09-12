/**
 * Supabase Authentication Service — TraceX Access Control
 *
 * Talks to the Supabase Auth REST API (/{project}/auth/v1) directly via fetch,
 * so no SDK dependency is required. Handles:
 *  - Email + password registration & sign-in
 *  - Google (Gmail) OAuth sign-in via the Supabase authorize endpoint
 *  - Session persistence (localStorage) + revalidation on boot
 *
 * @license Apache-2.0
 */

// ---------------------------------------------------------------------------
// Project configuration
// ---------------------------------------------------------------------------
const SUPABASE_URL = 'https://dtrgsngsgklzqibchqpn.supabase.co';
const SUPABASE_PUBLISHABLE_KEY = 'sb_publishable_NpwSdNWaPzedmNhzoe2pdQ_Qo6uRHuS';

const AUTH_BASE = `${SUPABASE_URL}/auth/v1`;
const SESSION_STORAGE_KEY = 'tracex.supabase.session';

// ---------------------------------------------------------------------------
// Types (subset of the Supabase auth payload we consume)
// ---------------------------------------------------------------------------
export interface SupabaseUser {
  id: string;
  email: string | null;
  phone?: string;
  aud?: string;
  role?: string;
  email_confirmed_at?: string | null;
  confirmed_at?: string | null;
  last_sign_in_at?: string | null;
  created_at?: string;
  updated_at?: string;
  user_metadata?: Record<string, unknown>;
  app_metadata?: Record<string, unknown>;
}

export interface AuthSession {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  expires_at?: number;
  token_type: string;
  user: SupabaseUser | null;
}

export interface AuthResult {
  session: AuthSession | null;
  /** Present when Supabase responds with an error */
  error: string | null;
  /** True when registration succeeded but requires email confirmation */
  needsConfirmation?: boolean;
}

// ---------------------------------------------------------------------------
// Low-level request helper
// ---------------------------------------------------------------------------
function baseHeaders(accessToken?: string | null): Record<string, string> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    apikey: SUPABASE_PUBLISHABLE_KEY,
    Authorization: `Bearer ${accessToken || SUPABASE_PUBLISHABLE_KEY}`,
  };
  return headers;
}

async function parseResponse<T>(res: Response): Promise<{ data: T | null; error: string | null }> {
  let body: unknown = null;
  try {
    body = await res.json();
  } catch {
    // Some error responses may be empty
  }

  if (!res.ok) {
    const err = body as { msg?: string; message?: string; error_description?: string; error?: string; code?: string } | null;
    const message =
      err?.msg ||
      err?.message ||
      err?.error_description ||
      err?.error ||
      `AUTH REQUEST FAILED (HTTP ${res.status})`;
    return { data: null, error: String(message).toUpperCase() };
  }

  return { data: body as T, error: null };
}

// ---------------------------------------------------------------------------
// Session persistence
// ---------------------------------------------------------------------------
export function persistSession(session: AuthSession): void {
  try {
    localStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(session));
  } catch {
    // Storage unavailable — session stays memory-only
  }
}

export function clearStoredSession(): void {
  try {
    localStorage.removeItem(SESSION_STORAGE_KEY);
  } catch {
    // Ignore
  }
}

export function getStoredSession(): AuthSession | null {
  try {
    const raw = localStorage.getItem(SESSION_STORAGE_KEY);
    if (!raw) return null;
    const session = JSON.parse(raw) as AuthSession;
    if (!session?.access_token) return null;
    // Expired?
    if (session.expires_at && session.expires_at * 1000 < Date.now()) {
      clearStoredSession();
      return null;
    }
    return session;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Email + password auth
// ---------------------------------------------------------------------------
export async function signUpWithPassword(email: string, password: string): Promise<AuthResult> {
  try {
    const res = await fetch(`${AUTH_BASE}/signup`, {
      method: 'POST',
      headers: baseHeaders(),
      body: JSON.stringify({ email, password }),
    });
    const { data, error } = await parseResponse<{ user: SupabaseUser; session: AuthSession | null }>(res);
    if (error) return { session: null, error };

    // When email confirmation is enabled, Supabase returns a user but NO session.
    if (data?.session) {
      persistSession(data.session);
      return { session: data.session, error: null };
    }
    return { session: null, error: null, needsConfirmation: true };
  } catch (e) {
    return { session: null, error: `NETWORK ERROR: ${(e as Error).message}`.toUpperCase() };
  }
}

export async function signInWithPassword(email: string, password: string): Promise<AuthResult> {
  try {
    const res = await fetch(`${AUTH_BASE}/token?grant_type=password`, {
      method: 'POST',
      headers: baseHeaders(),
      body: JSON.stringify({ email, password }),
    });
    const { data, error } = await parseResponse<AuthSession>(res);
    if (error) return { session: null, error };
    if (data?.access_token) {
      persistSession(data);
      return { session: data, error: null };
    }
    return { session: null, error: 'SIGN-IN FAILED: NO SESSION RETURNED' };
  } catch (e) {
    return { session: null, error: `NETWORK ERROR: ${(e as Error).message}`.toUpperCase() };
  }
}

// ---------------------------------------------------------------------------
// Google (Gmail) OAuth — implicit flow
// ---------------------------------------------------------------------------
/**
 * Redirects the browser to Supabase's OAuth authorize endpoint for Google.
 * On success Supabase redirects back to `redirectTo` with tokens in the URL
 * hash fragment (implicit flow), which `resolveOAuthRedirect()` picks up.
 */
export function signInWithGoogle(): void {
  const redirectTo = `${window.location.origin}${window.location.pathname}`;
  const url =
    `${AUTH_BASE}/authorize?provider=google` +
    `&redirect_to=${encodeURIComponent(redirectTo)}` +
    `&response_type=token`;
  window.location.href = url;
}

/**
 * Called once at app boot. If the URL hash contains an OAuth callback
 * (access_token + refresh_token), converts it into a persisted session and
 * cleans the URL. Returns the session when a redirect was detected.
 */
export function resolveOAuthRedirect(): AuthSession | null {
  try {
    if (!window.location.hash || window.location.hash.length < 2) return null;
    const params = new URLSearchParams(window.location.hash.substring(1));

    // OAuth error callback (e.g. provider disabled, redirect misconfigured):
    // arrives WITHOUT access_token — record it so the login page can surface it.
    const oauthError = params.get('error_description') || params.get('error');
    if (oauthError) {
      try {
        localStorage.setItem('tracex.supabase.oauth_error', oauthError);
      } catch { /* ignore */ }
      window.history.replaceState({}, document.title, window.location.pathname + window.location.search);
      return null;
    }

    const accessToken = params.get('access_token');
    if (!accessToken) return null;

    const expiresIn = Number(params.get('expires_in') || 3600);
    const session: AuthSession = {
      access_token: accessToken,
      refresh_token: params.get('refresh_token') || '',
      expires_in: expiresIn,
      expires_at: Math.floor(Date.now() / 1000) + expiresIn,
      token_type: params.get('token_type') || 'bearer',
      user: null,
    };

    // Best-effort: decode the embedded userinfo claims if present
    try {
      const payloadPart = accessToken.split('.')[1];
      if (payloadPart) {
        const claims = JSON.parse(atob(payloadPart.replace(/-/g, '+').replace(/_/g, '/')));
        session.user = {
          id: String(claims.sub || ''),
          email: claims.email ? String(claims.email) : null,
          email_confirmed_at: claims.email_verified ? new Date().toISOString() : null,
          user_metadata: {
            full_name: claims.name,
            avatar_url: claims.picture,
            provider_id: claims.provider_id,
          },
          app_metadata: { provider: claims.iss?.includes('google') ? 'google' : 'email' },
        };
      }
    } catch {
      // Claims unavailable — user profile can still be fetched via /auth/v1/user
    }

    persistSession(session);
    // Clean the hash so refreshes don't re-process the callback
    window.history.replaceState({}, document.title, window.location.pathname + window.location.search);
    return session;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Session validation / user fetch / sign-out
// ---------------------------------------------------------------------------
/** Revalidates a stored session against Supabase. Returns null if invalid. */
export async function fetchUser(accessToken: string): Promise<SupabaseUser | null> {
  try {
    const res = await fetch(`${AUTH_BASE}/user`, { headers: baseHeaders(accessToken) });
    if (!res.ok) return null;
    const { data, error } = await parseResponse<SupabaseUser>(res);
    return error ? null : data;
  } catch {
    return null;
  }
}

export async function validateSession(session: AuthSession): Promise<AuthSession | null> {
  const user = await fetchUser(session.access_token);
  if (!user) {
    clearStoredSession();
    return null;
  }
  const refreshed: AuthSession = { ...session, user };
  persistSession(refreshed);
  return refreshed;
}

export async function signOut(accessToken: string | null): Promise<void> {
  try {
    if (accessToken) {
      await fetch(`${AUTH_BASE}/logout`, {
        method: 'POST',
        headers: baseHeaders(accessToken),
        body: JSON.stringify({}),
      });
    }
  } catch {
    // Even if the server call fails, drop the local session
  }
  clearStoredSession();
}

/** Reads and clears any OAuth error recorded during redirect handling. */
export function consumeOAuthError(): string | null {
  try {
    const err = localStorage.getItem('tracex.supabase.oauth_error');
    if (err) {
      localStorage.removeItem('tracex.supabase.oauth_error');
      return err.toUpperCase();
    }
  } catch { /* ignore */ }
  return null;
}

/** Convenience: derive an operator display label from a user record. */
export function deriveOperatorLabel(user: SupabaseUser | null): string {
  if (!user) return 'OPERATOR';
  const metaName = user.user_metadata?.full_name;
  if (typeof metaName === 'string' && metaName.trim()) {
    return metaName.trim().split(/\s+/)[0].toUpperCase();
  }
  if (user.email) {
    const local = user.email.split('@')[0];
    return local.split(/[._-]/)[0].toUpperCase();
  }
  return 'OPERATOR';
}
