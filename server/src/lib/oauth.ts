// OAuth2 provider framework: registry of device-flow providers, the RFC 8628
// device-authorization state machine, token refresh, and the getValidAccessToken
// hot path provider adapters call on every request.
//
// CREDENTIAL MODEL
// ----------------
// An OAuth api_keys row stores its credential in encrypted_key as an AES-GCM
// blob whose PLAINTEXT is a JSON document — the contract owned by
// lib/oauth-credentials.ts ({v:1, provider, access_token, refresh_token?,
// expires_at, email?, ...extras}). This module owns only the fetch/refresh
// side: given that JSON string it returns a live access token, refreshing and
// persisting through persistOAuthCredential when a keyId is supplied.
//
// DEVICE FLOW STATE
// -----------------
// beginDeviceFlow / getDeviceFlowStatus keep flow state in an in-memory Map —
// the same ephemeral-state pattern as the codebase's other short-lived
// objects (one-time codes, probes). A flow lives only for its ~15-minute
// device-code lifetime, so persisting it to SQLite would add schema for state
// that is dead before the next boot. The trade-off: a server restart abandons
// in-flight enrollments; the user simply starts a new flow. getDeviceFlowStatus
// polls upstream AT MOST ONCE per advertised intervalSec (the RFC 8628
// slow_down contract) and caches the pending response between polls.
//
// RFC 8628 error mapping (token endpoint):
//   authorization_pending → keep polling
//   slow_down             → keep polling (interval bump handled client-side;
//                           we honor it by treating it identically to pending)
//   expired_token         → flow is dead
//   access_denied         → user declined
//   invalid_grant / other → terminal failure

import {
  oauthCredentialNeedsRefresh,
  parseOAuthCredential,
  persistOAuthCredential,
  type OAuthCredential,
} from './oauth-credentials.js';
import crypto from 'node:crypto';

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export type OAuthErrorCode =
  | 'invalid_grant'
  | 'refresh_failed'
  | 'device_flow_unsupported'
  | 'device_flow_expired'
  | 'device_flow_denied'
  | 'device_flow_error'
  | 'enrich_failed'
  | 'unknown_provider'
  | 'invalid_credential';

export class OAuthError extends Error {
  constructor(
    public readonly code: OAuthErrorCode,
    message: string,
    public readonly httpStatus?: number,
  ) {
    super(message);
    this.name = 'OAuthError';
  }
}

// ---------------------------------------------------------------------------
// Provider registry
// ---------------------------------------------------------------------------

export interface OAuthProviderConfig {
  slug: string;                    // 'antigravity'
  displayName: string;
  // Enrollment flow: 'device' = RFC 8628 device authorization grant;
  // 'authcode' = authorization-code + PKCE with a caller-supplied redirect.
  flow?: 'device' | 'authcode';
  // device authorization grant (RFC 8628) — optional per provider
  deviceEndpoint?: string;
  // authcode flow endpoints — required when flow === 'authcode'
  authEndpoint?: string;
  /** Path the provider's redirect_uri must end with (e.g.
   *  '/api/oauth/antigravity/callback'); the caller supplies the origin. */
  redirectPath?: string;
  clientId: string;
  clientSecret?: string;
  scopes: string[];
  extraAuthParams?: Record<string, string>;
  tokenEndpoint: string;
  // optional post-enrollment hook: exchange/refresh returns credential extras
  // (antigravity: loadCodeAssist → project_id, onboardUser when needed)
  enrichCredential?: (accessToken: string, cred: OAuthCredential) => Promise<OAuthCredential>;
  // optional per-provider token-endpoint user-agent (defaults to none);
  // providers mimicking a CLI set their own.
  tokenUserAgent?: string;
}

/** UA strings used against Google's Cloud Code Assist (matches the
 *  antigravity provider's outbound UA convention). */
const ANTIGRAVITY_IDE_UA =
  'antigravity/hub/2.29.0 (aidev_client; os_type=linux; arch=x64)';
const CODE_ASSIST_BASE = 'https://cloudcode-pa.googleapis.com/v1internal';

function loadCodeAssistProject(data: Record<string, unknown>): string | null {
  // CLIProxyAPI reads the project from whichever of these the API returns.
  for (const key of ['cloudaicompanionProject', 'projectId', 'project']) {
    const value = data[key];
    if (typeof value === 'string' && value) return value;
    if (typeof value === 'object' && value !== null) {
      const inner = (value as Record<string, unknown>).id ?? (value as Record<string, unknown>).name;
      if (typeof inner === 'string' && inner) return inner;
    }
  }
  return null;
}

interface CodeAssistTier {
  id?: string;
  isDefault?: boolean;
}

function pickTier(data: Record<string, unknown>): string {
  const tiers = Array.isArray(data.allowedTiers) ? (data.allowedTiers as CodeAssistTier[]) : [];
  const def = tiers.find(t => t.isDefault === true && typeof t.id === 'string' && t.id);
  if (def?.id) return def.id;
  const current = data.currentTier as Record<string, unknown> | undefined;
  if (current && typeof current.id === 'string' && current.id) return current.id;
  return 'free-tier';
}

async function onboardUser(accessToken: string): Promise<Record<string, unknown>> {
  // :onboardUser is asynchronous upstream — the first POST kicks it off and
  // subsequent calls report progress until completeUserOnboarding flips true.
  // Poll up to ~20 attempts; interval comes from the response or defaults 2s.
  let tierId = 'free-tier';
  for (let attempt = 0; attempt < 20; attempt++) {
    const res = await fetch(`${CODE_ASSIST_BASE}:onboardUser`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
        'User-Agent': ANTIGRAVITY_IDE_UA,
      },
      body: JSON.stringify({ tierId, metadata: { ideType: 'ANTIGRAVITY' } }),
    });
    const data = (await res.json().catch(() => ({}))) as Record<string, unknown>;
    if (!res.ok) {
      throw new OAuthError('enrich_failed', `Antigravity onboardUser failed: HTTP ${res.status}`, res.status);
    }
    if (data.complete === true || data.completeUserOnboarding === true) return data;
    // The response may carry the tier list on later polls; feed it back.
    if (Array.isArray(data.allowedTiers)) tierId = pickTier(data);
    const waitSec = typeof data.pollingIntervalSeconds === 'number' ? data.pollingIntervalSeconds : 2;
    await new Promise(resolve => setTimeout(resolve, Math.min(Math.max(waitSec, 1), 10) * 1000));
  }
  throw new OAuthError('enrich_failed', 'Antigravity onboardUser did not complete within the poll budget');
}

async function postCodeAssist(path: string, accessToken: string): Promise<Record<string, unknown>> {
  const res = await fetch(`${CODE_ASSIST_BASE}:${path}`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
      'User-Agent': ANTIGRAVITY_IDE_UA,
    },
    body: JSON.stringify({ metadata: { ideType: 'ANTIGRAVITY' } }),
  });
  const data = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  if (!res.ok) {
    throw new OAuthError('enrich_failed', `Antigravity ${path} failed: HTTP ${res.status}`, res.status);
  }
  return data;
}

async function antigravityEnrichCredential(accessToken: string, cred: OAuthCredential): Promise<OAuthCredential> {
  // loadCodeAssist tells us which GCP project this account may bill against.
  const data = await postCodeAssist('loadCodeAssist', accessToken);
  let projectId = loadCodeAssistProject(data);
  if (!projectId) {
    // No project yet — run onboarding to provision one, then re-check.
    await onboardUser(accessToken);
    const recheck = await postCodeAssist('loadCodeAssist', accessToken);
    projectId = loadCodeAssistProject(recheck);
    void pickTier(recheck); // tier is advisory; recorded implicitly via onboard
  }
  if (projectId) cred.project_id = projectId;
  return cred;
}

export const OAUTH_PROVIDERS: Record<string, OAuthProviderConfig> = {
  antigravity: {
    slug: 'antigravity',
    displayName: 'Google Antigravity',
    // Google's OAuth client for this slug does not support the RFC 8628
    // device grant (invalid_client on /device/code) — CLIProxyAPI uses the
    // authorization-code + PKCE flow with a localhost redirect instead.
    flow: 'authcode',
    authEndpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
    redirectPath: '/api/oauth/antigravity/callback',
    clientId: '1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com',
    // Public installed-app OAuth client (same credentials CLIProxyAPI ships).
    // The secret is read from env so it never lands in the repo — set
    // ANTIGRAVITY_CLIENT_SECRET in the deployment environment.
    clientSecret: process.env.ANTIGRAVITY_CLIENT_SECRET,
    scopes: [
      'https://www.googleapis.com/auth/cloud-platform',
      'https://www.googleapis.com/auth/userinfo.email',
      'https://www.googleapis.com/auth/userinfo.profile',
      'https://www.googleapis.com/auth/aicode',
      'https://www.googleapis.com/auth/cclog',
      'https://www.googleapis.com/auth/experimentsandconfigs',
    ],
    tokenEndpoint: 'https://oauth2.googleapis.com/token',
    enrichCredential: antigravityEnrichCredential,
  },
};

// ---------------------------------------------------------------------------
// Low-level OAuth HTTP
// ---------------------------------------------------------------------------

interface TokenResponse {
  access_token?: string;
  refresh_token?: string;
  expires_in?: number;
  token_type?: string;
  error?: string;
  error_description?: string;
}

async function requestDeviceCode(
  provider: OAuthProviderConfig,
): Promise<{ deviceCode: string; userCode: string; verificationUri: string; intervalSec: number; expiresInSec: number }> {
  if (!provider.deviceEndpoint) {
    throw new OAuthError('device_flow_unsupported', `Provider '${provider.slug}' has no device authorization endpoint`);
  }
  const params: Record<string, string> = {
    client_id: provider.clientId,
    scope: provider.scopes.join(' '),
  };
  if (provider.clientSecret) params.client_secret = provider.clientSecret;
  if (provider.extraAuthParams) Object.assign(params, provider.extraAuthParams);

  const res = await fetch(provider.deviceEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
    body: new URLSearchParams(params).toString(),
  });
  const data = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  if (!res.ok || typeof data.device_code !== 'string' || typeof data.user_code !== 'string') {
    const err = typeof data.error === 'string' ? data.error : `HTTP ${res.status}`;
    const desc = typeof data.error_description === 'string' ? data.error_description : '';
    throw new OAuthError('device_flow_error', `Device authorization failed: ${err}${desc ? ` — ${desc}` : ''}`, res.status);
  }
  const verificationUri =
    (typeof data.verification_url === 'string' && data.verification_url) ||
    (typeof data.verification_uri === 'string' && data.verification_uri) ||
    '';
  if (!verificationUri) {
    throw new OAuthError('device_flow_error', 'Device authorization response missing verification URL');
  }
  return {
    deviceCode: data.device_code,
    userCode: data.user_code,
    verificationUri,
    intervalSec: typeof data.interval === 'number' ? data.interval : 5,
    expiresInSec: typeof data.expires_in === 'number' ? data.expires_in : 1800,
  };
}

async function pollDeviceToken(
  provider: OAuthProviderConfig,
  deviceCode: string,
): Promise<{ pending: true } | { pending: false; credential?: OAuthCredential; error?: OAuthError }> {
  const params: Record<string, string> = {
    grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
    device_code: deviceCode,
    client_id: provider.clientId,
  };
  if (provider.clientSecret) params.client_secret = provider.clientSecret;
  if (provider.extraAuthParams) Object.assign(params, provider.extraAuthParams);

  const res = await fetch(provider.tokenEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Accept': 'application/json',
      ...(provider.tokenUserAgent ? { 'User-Agent': provider.tokenUserAgent } : {}),
    },
    body: new URLSearchParams(params).toString(),
  });
  const data = (await res.json().catch(() => ({}))) as TokenResponse;

  if (res.ok && typeof data.access_token === 'string') {
    return {
      pending: false,
      credential: {
        v: 1,
        provider: provider.slug,
        access_token: data.access_token,
        ...(typeof data.refresh_token === 'string' ? { refresh_token: data.refresh_token } : {}),
        expires_at: Date.now() + (typeof data.expires_in === 'number' ? data.expires_in : 3600) * 1000,
      },
    };
  }

  const error = data.error ?? '';
  const description = data.error_description ?? '';
  if (error === 'authorization_pending' || error === 'slow_down') return { pending: true };
  if (error === 'expired_token') {
    return { pending: false, error: new OAuthError('device_flow_expired', 'Device code expired', res.status) };
  }
  if (error === 'access_denied') {
    return { pending: false, error: new OAuthError('device_flow_denied', 'Device authorization was denied', res.status) };
  }
  if (error === 'invalid_grant') {
    return { pending: false, error: new OAuthError('invalid_grant', description || 'Token grant rejected', res.status) };
  }
  return {
    pending: false,
    error: new OAuthError('device_flow_error', description || `Device token poll failed: ${error || `HTTP ${res.status}`}`, res.status),
  };
}

// ---------------------------------------------------------------------------
// Auth-code (PKCE) flow — for providers whose OAuth client rejects the device
// grant (Google's Antigravity client returns invalid_client on /device/code).
// Same in-memory state rationale as the device flows; entries are single-use
// and expire after ~10 minutes (the practical lifetime of an auth URL).
// ---------------------------------------------------------------------------

export interface AuthCodeFlowStart {
  flowId: string;
  authUrl: string;
}

interface AuthCodeFlowState {
  provider: OAuthProviderConfig;
  codeVerifier: string;
  redirectUri: string;
  expiresAt: number;
}

const AUTH_CODE_TTL_MS = 10 * 60 * 1000;

function b64url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export async function beginAuthCodeFlow(providerSlug: string, redirectUri: string): Promise<AuthCodeFlowStart> {
  const provider = OAUTH_PROVIDERS[providerSlug];
  if (!provider) throw new OAuthError('unknown_provider', `Unknown OAuth provider '${providerSlug}'`);
  if ((provider.flow ?? 'device') !== 'authcode') {
    throw new OAuthError('device_flow_unsupported', `Provider '${providerSlug}' does not use the authcode flow`);
  }
  if (!provider.authEndpoint) {
    throw new OAuthError('device_flow_unsupported', `Provider '${providerSlug}' has no auth endpoint`);
  }
  // redirect_uri must be http(s) and land on the provider's registered path.
  let parsed: URL;
  try {
    parsed = new URL(redirectUri);
  } catch {
    throw new OAuthError('device_flow_error', 'redirectUri is not a valid URL');
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new OAuthError('device_flow_error', 'redirectUri must be http(s)');
  }
  if (provider.redirectPath && parsed.pathname !== provider.redirectPath) {
    throw new OAuthError('device_flow_error', `redirectUri path must be ${provider.redirectPath}`);
  }

  // PKCE S256: verifier is 32 random bytes b64url; challenge is its sha256.
  const codeVerifier = b64url(crypto.randomBytes(32));
  const codeChallenge = b64url(crypto.createHash('sha256').update(codeVerifier).digest());

  const flowId = `ac_${Date.now().toString(36)}_${(++flowCounter).toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
  authCodeFlows.set(flowId, {
    provider,
    codeVerifier,
    redirectUri,
    expiresAt: Date.now() + AUTH_CODE_TTL_MS,
  });
  ensureSweeper();

  const params = new URLSearchParams({
    client_id: provider.clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: provider.scopes.join(' '),
    access_type: 'offline',
    prompt: 'consent',
    state: flowId,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  });
  if (provider.extraAuthParams) {
    for (const [k, v] of Object.entries(provider.extraAuthParams)) params.set(k, v);
  }
  return { flowId, authUrl: `${provider.authEndpoint}?${params.toString()}` };
}

export type AuthCodeCompletion =
  | { status: 'ok'; credential: OAuthCredential }
  | { status: 'pending' }
  | { status: 'error'; message: string }
  | { status: 'expired' };

/**
 * Exchange the authorization code returned to the redirect for tokens.
 * The `state` param is the flowId minted by beginAuthCodeFlow. Flow state is
 * single-use: the entry is deleted whether the exchange succeeds or fails.
 */
export async function handleAuthCodeCallback(
  providerSlug: string,
  code: string,
  state: string,
  redirectUri: string,
): Promise<AuthCodeCompletion> {
  const flow = authCodeFlows.get(state);
  if (!flow) return { status: 'expired' };
  if (flow.expiresAt <= Date.now() || flow.provider.slug !== providerSlug) {
    authCodeFlows.delete(state);
    return { status: 'expired' };
  }
  if (flow.redirectUri !== redirectUri) {
    authCodeFlows.delete(state);
    return { status: 'error', message: 'redirect_uri does not match the flow' };
  }

  const provider = flow.provider;
  const params: Record<string, string> = {
    grant_type: 'authorization_code',
    code,
    client_id: provider.clientId,
    redirect_uri: redirectUri,
    code_verifier: flow.codeVerifier,
  };
  if (provider.clientSecret) params.client_secret = provider.clientSecret;
  if (provider.extraAuthParams) Object.assign(params, provider.extraAuthParams);

  let res: Response;
  try {
    res = await fetch(provider.tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
        ...(provider.tokenUserAgent ? { 'User-Agent': provider.tokenUserAgent } : {}),
      },
      body: new URLSearchParams(params).toString(),
    });
  } catch (err) {
    authCodeFlows.delete(state);
    return { status: 'error', message: `Token exchange failed: ${(err as Error).message}` };
  }
  const data = (await res.json().catch(() => ({}))) as TokenResponse;
  authCodeFlows.delete(state); // single-use regardless of outcome

  if (!res.ok || typeof data.access_token !== 'string') {
    const error = data.error ?? '';
    const description = data.error_description ?? '';
    return {
      status: 'error',
      message: description || `Token exchange failed: ${error || `HTTP ${res.status}`}`,
    };
  }

  let credential: OAuthCredential = {
    v: 1,
    provider: provider.slug,
    access_token: data.access_token,
    ...(typeof data.refresh_token === 'string' ? { refresh_token: data.refresh_token } : {}),
    expires_at: Date.now() + (typeof data.expires_in === 'number' ? data.expires_in : 3600) * 1000,
  };
  if (provider.enrichCredential) {
    try {
      credential = await provider.enrichCredential(credential.access_token, credential);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { status: 'error', message: `Enrollment enrichment failed: ${message}` };
    }
  }
  return { status: 'ok', credential };
}

// ---------------------------------------------------------------------------
// Device-flow state machine (in-memory; see header for rationale)
// ---------------------------------------------------------------------------

export interface DeviceFlowStart {
  flowId: string;
  verificationUri: string;
  userCode: string;
  intervalSec: number;
  expiresAt: number;
}

interface DeviceFlowState {
  provider: OAuthProviderConfig;
  deviceCode: string;
  intervalSec: number;
  expiresAt: number;
  lastPollAt: number;
  /** Cached terminal outcome so repeat status calls don't re-poll upstream. */
  outcome?: 'complete' | 'error' | 'expired';
  credential?: OAuthCredential;
  errorMessage?: string;
}

const deviceFlows = new Map<string, DeviceFlowState>();
const authCodeFlows = new Map<string, AuthCodeFlowState>();
let flowCounter = 0;
let sweeper: NodeJS.Timeout | null = null;

function ensureSweeper(): void {
  if (sweeper) return;
  sweeper = setInterval(() => {
    const now = Date.now();
    for (const [id, state] of deviceFlows) {
      if (state.expiresAt <= now) deviceFlows.delete(id);
    }
    for (const [id, state] of authCodeFlows) {
      if (state.expiresAt <= now) authCodeFlows.delete(id);
    }
  }, 30_000);
  sweeper.unref();
}

export async function beginDeviceFlow(providerSlug: string): Promise<DeviceFlowStart> {
  const provider = OAUTH_PROVIDERS[providerSlug];
  if (!provider) throw new OAuthError('unknown_provider', `Unknown OAuth provider '${providerSlug}'`);
  const start = await requestDeviceCode(provider);
  const flowId = `of_${Date.now().toString(36)}_${(++flowCounter).toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
  const expiresAt = Date.now() + start.expiresInSec * 1000;
  deviceFlows.set(flowId, {
    provider,
    deviceCode: start.deviceCode,
    intervalSec: start.intervalSec,
    expiresAt,
    lastPollAt: 0,
  });
  ensureSweeper();
  return {
    flowId,
    verificationUri: start.verificationUri,
    userCode: start.userCode,
    intervalSec: start.intervalSec,
    expiresAt,
  };
}

export type DeviceFlowStatus =
  | { status: 'pending' }
  | { status: 'complete'; credential: OAuthCredential }
  | { status: 'error'; message: string }
  | { status: 'expired' };

export async function getDeviceFlowStatus(flowId: string): Promise<DeviceFlowStatus> {
  const state = deviceFlows.get(flowId);
  if (!state) return { status: 'expired' };
  if (state.expiresAt <= Date.now()) {
    deviceFlows.delete(flowId);
    return { status: 'expired' };
  }
  // Terminal states are sticky — return the cached outcome without re-polling.
  if (state.outcome === 'complete' && state.credential) {
    return { status: 'complete', credential: state.credential };
  }
  if (state.outcome === 'error') {
    return { status: 'error', message: state.errorMessage ?? 'Device flow failed' };
  }
  if (state.outcome === 'expired') return { status: 'expired' };

  // Rate-limit upstream polls to once per intervalSec (RFC 8628 §3.5).
  const now = Date.now();
  if (state.lastPollAt && now - state.lastPollAt < state.intervalSec * 1000) {
    return { status: 'pending' };
  }
  state.lastPollAt = now;

  try {
    const result = await pollDeviceToken(state.provider, state.deviceCode);
    if (result.pending) {
      return { status: 'pending' };
    }
    if (result.error) {
      if (result.error.code === 'device_flow_expired') {
        state.outcome = 'expired';
        deviceFlows.delete(flowId);
        return { status: 'expired' };
      }
      state.outcome = 'error';
      state.errorMessage = result.error.message;
      return { status: 'error', message: result.error.message };
    }
    let credential = result.credential;
    if (!credential) {
      state.outcome = 'error';
      state.errorMessage = 'Device flow completed without a credential';
      return { status: 'error', message: state.errorMessage };
    }
    if (state.provider.enrichCredential) {
      try {
        credential = await state.provider.enrichCredential(credential.access_token, credential);
      } catch (err) {
        state.outcome = 'error';
        const message = err instanceof Error ? err.message : String(err);
        state.errorMessage = `Enrollment enrichment failed: ${message}`;
        return { status: 'error', message: state.errorMessage };
      }
    }
    state.credential = credential;
    state.outcome = 'complete';
    return { status: 'complete', credential };
  } catch (err) {
    // Transport failure on the poll is not fatal — the flow stays pending and
    // the next eligible poll retries. Surface as pending so the client keeps
    // polling rather than abandoning a nearly-done enrollment.
    const message = err instanceof Error ? err.message : String(err);
    console.warn(`[oauth] device flow ${flowId} poll failed: ${message}`);
    return { status: 'pending' };
  }
}

export function cancelDeviceFlow(flowId: string): void {
  deviceFlows.delete(flowId);
}

// ---------------------------------------------------------------------------
// Refresh + hot path
// ---------------------------------------------------------------------------

export async function refreshAccessToken(cred: OAuthCredential): Promise<OAuthCredential> {
  const provider = OAUTH_PROVIDERS[cred.provider];
  if (!provider) {
    throw new OAuthError('unknown_provider', `No OAuth provider registered for '${cred.provider}'`);
  }
  if (!cred.refresh_token) {
    throw new OAuthError('invalid_grant', `Credential for '${cred.provider}' has no refresh_token`);
  }
  const params: Record<string, string> = {
    grant_type: 'refresh_token',
    refresh_token: cred.refresh_token,
    client_id: provider.clientId,
  };
  if (provider.clientSecret) params.client_secret = provider.clientSecret;
  if (provider.extraAuthParams) Object.assign(params, provider.extraAuthParams);

  let res: Response;
  try {
    res = await fetch(provider.tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
        ...(provider.tokenUserAgent ? { 'User-Agent': provider.tokenUserAgent } : {}),
      },
      body: new URLSearchParams(params).toString(),
    });
  } catch (err) {
    throw new OAuthError('refresh_failed', `Token refresh request failed: ${(err as Error).message}`);
  }
  const data = (await res.json().catch(() => ({}))) as TokenResponse;

  if (!res.ok || typeof data.access_token !== 'string') {
    const error = data.error ?? '';
    const description = data.error_description ?? '';
    if (error === 'invalid_grant') {
      throw new OAuthError('invalid_grant', description || 'Refresh token rejected', res.status);
    }
    throw new OAuthError('refresh_failed', description || `Token refresh failed: ${error || `HTTP ${res.status}`}`, res.status);
  }

  const refreshed: OAuthCredential = {
    ...cred,
    access_token: data.access_token,
    // Some providers rotate the refresh token; keep the old one when absent.
    refresh_token: typeof data.refresh_token === 'string' ? data.refresh_token : cred.refresh_token,
    expires_at: Date.now() + (typeof data.expires_in === 'number' ? data.expires_in : 3600) * 1000,
  };
  if (provider.enrichCredential) {
    try {
      return await provider.enrichCredential(refreshed.access_token, refreshed);
    } catch {
      // Enrichment is best-effort on refresh — a project_id already stored on
      // the credential survives via the spread above.
    }
  }
  return refreshed;
}

/**
 * Hot path for provider adapters: returns a live access token for an
 * api_keys.encrypted_key plaintext blob.
 *
 * Cheap when fresh — parse + compare, no I/O. When the token is inside the
 * refresh margin (or expired) it performs a refresh_token grant; with keyId
 * the rotated blob is persisted back to api_keys via persistOAuthCredential,
 * without it the new token is returned unpersisted.
 *
 * Throws OAuthError — provider adapters map it onto their providerHttpError
 * shape so the router benches the key normally.
 */
export async function getValidAccessToken(
  apiKeyJson: string,
  keyId?: number,
): Promise<{ accessToken: string; credential: OAuthCredential }> {
  const cred = parseOAuthCredential(apiKeyJson);
  if (!cred) {
    throw new OAuthError('invalid_credential', 'API key is not an OAuth credential blob');
  }
  if (!oauthCredentialNeedsRefresh(cred)) {
    return { accessToken: cred.access_token, credential: cred };
  }
  const refreshed = await refreshAccessToken(cred);
  if (keyId !== undefined) {
    persistOAuthCredential(keyId, refreshed);
  }
  return { accessToken: refreshed.access_token, credential: refreshed };
}
