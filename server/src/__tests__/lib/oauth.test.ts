import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  OAUTH_PROVIDERS,
  beginAuthCodeFlow,
  beginDeviceFlow,
  getDeviceFlowStatus,
  cancelDeviceFlow,
  getValidAccessToken,
  handleAuthCodeCallback,
  refreshAccessToken,
} from '../../lib/oauth.js';
import { serializeOAuthCredential, type OAuthCredential } from '../../lib/oauth-credentials.js';
import { initDb, getDb } from '../../db/index.js';
import { decrypt, encrypt } from '../../lib/crypto.js';

const realFetch = globalThis.fetch;

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

/** Register a throwaway provider for tests so the antigravity enrich hook
 *  (loadCodeAssist/onboardUser) doesn't fire. */
function registerTestProvider(slug = 'testoauth') {
  OAUTH_PROVIDERS[slug] = {
    slug,
    displayName: 'Test OAuth',
    deviceEndpoint: 'https://idp.test/device/code',
    clientId: 'test-client',
    clientSecret: 'test-secret',
    scopes: ['scope.a', 'scope.b'],
    tokenEndpoint: 'https://idp.test/token',
  };
  return slug;
}

/** Authcode-flow provider with a local enrich stub (no network). */
function registerAuthCodeProvider(slug = 'testauth') {
  OAUTH_PROVIDERS[slug] = {
    slug,
    displayName: 'Test Auth OAuth',
    flow: 'authcode',
    authEndpoint: 'https://idp.test/o/oauth2/auth',
    redirectPath: `/api/oauth/${slug}/callback`,
    clientId: 'auth-client',
    clientSecret: 'auth-secret',
    scopes: ['scope.a'],
    tokenEndpoint: 'https://idp.test/token',
    enrichCredential: async (_at, cred) => ({ ...cred, project_id: 'proj-test' }),
  };
  return slug;
}

beforeEach(() => {
  process.env.ENCRYPTION_KEY = '0'.repeat(64);
  initDb(':memory:');
});

afterEach(() => {
  globalThis.fetch = realFetch;
  vi.restoreAllMocks();
  delete OAUTH_PROVIDERS.testoauth;
  delete OAUTH_PROVIDERS.testoauth2;
  delete OAUTH_PROVIDERS.testauth;
  delete OAUTH_PROVIDERS.testauth2;
});

describe('device flow state machine', () => {
  it('begin → pending → complete round-trip', async () => {
    const slug = registerTestProvider();
    const fetchMock = vi.fn()
      // device/code
      .mockResolvedValueOnce(jsonResponse({
        device_code: 'dev-1',
        user_code: 'ABCD-EFGH',
        verification_url: 'https://idp.test/activate',
        interval: 1,
        expires_in: 600,
      }))
      // token poll #1: pending
      .mockResolvedValueOnce(jsonResponse({ error: 'authorization_pending' }, 400))
      // token poll #2: success
      .mockResolvedValueOnce(jsonResponse({
        access_token: 'at-1',
        refresh_token: 'rt-1',
        expires_in: 3600,
        token_type: 'Bearer',
      }));
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const start = await beginDeviceFlow(slug);
    expect(start.flowId).toMatch(/^of_/);
    expect(start.verificationUri).toBe('https://idp.test/activate');
    expect(start.userCode).toBe('ABCD-EFGH');
    expect(start.intervalSec).toBe(1);

    // First poll: upstream returns authorization_pending.
    const s1 = await getDeviceFlowStatus(start.flowId);
    expect(s1.status).toBe('pending');

    // Second poll within intervalSec is rate-limited client-side — no fetch.
    const s2 = await getDeviceFlowStatus(start.flowId);
    expect(s2.status).toBe('pending');
    expect(fetchMock).toHaveBeenCalledTimes(2); // device + 1 token poll

    // Wait out the interval, then poll again → complete.
    await new Promise(r => setTimeout(r, 1100));
    const s3 = await getDeviceFlowStatus(start.flowId);
    expect(s3.status).toBe('complete');
    if (s3.status === 'complete') {
      expect(s3.credential.access_token).toBe('at-1');
      expect(s3.credential.refresh_token).toBe('rt-1');
      expect(s3.credential.provider).toBe(slug);
      expect(s3.credential.v).toBe(1);
    }

    // Terminal state is sticky — no further upstream calls.
    const s4 = await getDeviceFlowStatus(start.flowId);
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it('slow_down is treated as pending', async () => {
    const slug = registerTestProvider('testoauth2');
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({
        device_code: 'dev-2', user_code: 'WXYZ', verification_url: 'https://idp.test/v', interval: 0, expires_in: 600,
      }))
      .mockResolvedValueOnce(jsonResponse({ error: 'slow_down' }, 400));
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const start = await beginDeviceFlow(slug);
    const status = await getDeviceFlowStatus(start.flowId);
    expect(status.status).toBe('pending');
  });

  it('expired_token ends the flow', async () => {
    const slug = registerTestProvider('testoauth2');
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({
        device_code: 'dev-3', user_code: 'PQRS', verification_url: 'https://idp.test/v', interval: 0, expires_in: 600,
      }))
      .mockResolvedValueOnce(jsonResponse({ error: 'expired_token' }, 400));
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const start = await beginDeviceFlow(slug);
    const status = await getDeviceFlowStatus(start.flowId);
    expect(status.status).toBe('expired');
    // Unknown flow afterwards also reads as expired.
    expect((await getDeviceFlowStatus(start.flowId)).status).toBe('expired');
  });

  it('access_denied surfaces as error', async () => {
    const slug = registerTestProvider('testoauth2');
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({
        device_code: 'dev-4', user_code: 'DENY', verification_url: 'https://idp.test/v', interval: 0, expires_in: 600,
      }))
      .mockResolvedValueOnce(jsonResponse({ error: 'access_denied' }, 400));
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const start = await beginDeviceFlow(slug);
    const status = await getDeviceFlowStatus(start.flowId);
    expect(status.status).toBe('error');
    if (status.status === 'error') expect(status.message).toMatch(/denied/i);
  });

  it('cancelDeviceFlow removes the flow', async () => {
    const slug = registerTestProvider('testoauth2');
    const fetchMock = vi.fn().mockResolvedValueOnce(jsonResponse({
      device_code: 'dev-5', user_code: 'CANCEL', verification_url: 'https://idp.test/v', interval: 0, expires_in: 600,
    }));
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const start = await beginDeviceFlow(slug);
    cancelDeviceFlow(start.flowId);
    expect((await getDeviceFlowStatus(start.flowId)).status).toBe('expired');
  });

  it('unknown provider slug throws OAuthError', async () => {
    await expect(beginDeviceFlow('nosuchprovider')).rejects.toMatchObject({
      name: 'OAuthError',
      code: 'unknown_provider',
    });
  });
});

describe('getValidAccessToken', () => {
  function seedKey(cred: OAuthCredential): number {
    const plaintext = serializeOAuthCredential(cred);
    const { encrypted, iv, authTag } = encrypt(plaintext);
    const result = getDb().prepare(`
      INSERT INTO api_keys (platform, label, encrypted_key, iv, auth_tag, status, enabled, oauth_provider, oauth_expires_at, oauth_email)
      VALUES (?, ?, ?, ?, ?, 'unknown', 1, ?, ?, ?)
    `).run('testoauth', 't', encrypted, iv, authTag, cred.provider, cred.expires_at, cred.email ?? null);
    return Number(result.lastInsertRowid);
  }

  const freshCred: OAuthCredential = {
    v: 1,
    provider: 'testoauth',
    access_token: 'fresh-at',
    refresh_token: 'rt',
    expires_at: Date.now() + 3600_000,
  };

  it('fresh credential returns access token with no fetch', async () => {
    const fetchMock = vi.fn();
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    const blob = serializeOAuthCredential(freshCred);
    const { accessToken, credential } = await getValidAccessToken(blob);
    expect(accessToken).toBe('fresh-at');
    expect(credential.access_token).toBe('fresh-at');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('non-OAuth blob throws invalid_credential', async () => {
    await expect(getValidAccessToken('sk-static-key')).rejects.toMatchObject({ code: 'invalid_credential' });
    await expect(getValidAccessToken('{"v":2,"provider":"x"}')).rejects.toMatchObject({ code: 'invalid_credential' });
  });

  it('expired credential refreshes and persists when keyId given', async () => {
    const slug = registerTestProvider();
    const expired: OAuthCredential = { ...freshCred, provider: slug, expires_at: Date.now() - 1000 };
    const keyId = seedKey(expired);

    const fetchMock = vi.fn().mockResolvedValueOnce(jsonResponse({
      access_token: 'new-at',
      refresh_token: 'new-rt',
      expires_in: 3600,
    }));
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const blob = serializeOAuthCredential(expired);
    const { accessToken, credential } = await getValidAccessToken(blob, keyId);
    expect(accessToken).toBe('new-at');
    expect(credential.refresh_token).toBe('new-rt');
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const body = String((fetchMock.mock.calls[0][1] as RequestInit).body);
    expect(body).toContain('grant_type=refresh_token');
    expect(body).toContain('refresh_token=rt');

    // Persisted: decrypt the row and check the rotated tokens landed.
    const row = getDb().prepare('SELECT encrypted_key, iv, auth_tag, oauth_expires_at FROM api_keys WHERE id = ?').get(keyId) as {
      encrypted_key: string; iv: string; auth_tag: string; oauth_expires_at: number;
    };
    const stored = JSON.parse(decrypt(row.encrypted_key, row.iv, row.auth_tag)) as OAuthCredential;
    expect(stored.access_token).toBe('new-at');
    expect(stored.refresh_token).toBe('new-rt');
    expect(row.oauth_expires_at).toBe(stored.expires_at);
  });

  it('refresh without keyId returns token but does not persist', async () => {
    const slug = registerTestProvider('testoauth2');
    const expired: OAuthCredential = { ...freshCred, provider: slug, expires_at: Date.now() - 1000 };
    const keyId = seedKey(expired);
    const before = getDb().prepare('SELECT encrypted_key FROM api_keys WHERE id = ?').get(keyId) as { encrypted_key: string };

    globalThis.fetch = vi.fn().mockResolvedValueOnce(jsonResponse({
      access_token: 'ephemeral-at', expires_in: 3600,
    })) as unknown as typeof fetch;

    const { accessToken } = await getValidAccessToken(serializeOAuthCredential(expired));
    expect(accessToken).toBe('ephemeral-at');
    const after = getDb().prepare('SELECT encrypted_key FROM api_keys WHERE id = ?').get(keyId) as { encrypted_key: string };
    expect(after.encrypted_key).toBe(before.encrypted_key);
  });

  it('invalid_grant maps to typed OAuthError', async () => {
    const slug = registerTestProvider('testoauth2');
    const expired: OAuthCredential = { ...freshCred, provider: slug, expires_at: Date.now() - 1000 };
    globalThis.fetch = vi.fn().mockResolvedValueOnce(jsonResponse({
      error: 'invalid_grant', error_description: 'Token has been expired or revoked.',
    }, 400)) as unknown as typeof fetch;

    await expect(getValidAccessToken(serializeOAuthCredential(expired)))
      .rejects.toMatchObject({ name: 'OAuthError', code: 'invalid_grant' });
  });

  it('credential inside refresh margin triggers refresh', async () => {
    const slug = registerTestProvider('testoauth2');
    // 30s left — inside the 60s margin.
    const nearExpiry: OAuthCredential = { ...freshCred, provider: slug, expires_at: Date.now() + 30_000 };
    globalThis.fetch = vi.fn().mockResolvedValueOnce(jsonResponse({
      access_token: 'margin-at', expires_in: 3600,
    })) as unknown as typeof fetch;

    const { accessToken } = await getValidAccessToken(serializeOAuthCredential(nearExpiry));
    expect(accessToken).toBe('margin-at');
  });
});

describe('refreshAccessToken', () => {
  it('keeps old refresh_token when response omits one', async () => {
    const slug = registerTestProvider('testoauth2');
    const cred: OAuthCredential = {
      v: 1, provider: slug, access_token: 'old', refresh_token: 'keep-rt',
      expires_at: Date.now() - 1000,
    };
    globalThis.fetch = vi.fn().mockResolvedValueOnce(jsonResponse({
      access_token: 'rotated', expires_in: 3600,
    })) as unknown as typeof fetch;

    const refreshed = await refreshAccessToken(cred);
    expect(refreshed.access_token).toBe('rotated');
    expect(refreshed.refresh_token).toBe('keep-rt');
  });

  it('throws refresh_failed on transport error', async () => {
    const slug = registerTestProvider('testoauth2');
    const cred: OAuthCredential = {
      v: 1, provider: slug, access_token: 'old', refresh_token: 'rt',
      expires_at: Date.now() - 1000,
    };
    globalThis.fetch = vi.fn(async () => { throw new Error('ECONNREFUSED'); }) as unknown as typeof fetch;
    await expect(refreshAccessToken(cred)).rejects.toMatchObject({ code: 'refresh_failed' });
  });

  it('unknown provider slug throws', async () => {
    const cred: OAuthCredential = {
      v: 1, provider: 'ghost', access_token: 'a', refresh_token: 'r', expires_at: 0,
    };
    await expect(refreshAccessToken(cred)).rejects.toMatchObject({ code: 'unknown_provider' });
  });
});

describe('authcode (PKCE) flow', () => {
  const REDIRECT = 'https://dash.test/api/oauth/testauth/callback';

  it('beginAuthCodeFlow returns authUrl with PKCE challenge and state', async () => {
    const slug = registerAuthCodeProvider();
    const start = await beginAuthCodeFlow(slug, REDIRECT);
    expect(start.flowId).toMatch(/^ac_/);
    const url = new URL(start.authUrl);
    expect(url.origin + url.pathname).toBe('https://idp.test/o/oauth2/auth');
    expect(url.searchParams.get('client_id')).toBe('auth-client');
    expect(url.searchParams.get('redirect_uri')).toBe(REDIRECT);
    expect(url.searchParams.get('response_type')).toBe('code');
    expect(url.searchParams.get('scope')).toBe('scope.a');
    expect(url.searchParams.get('access_type')).toBe('offline');
    expect(url.searchParams.get('prompt')).toBe('consent');
    expect(url.searchParams.get('state')).toBe(start.flowId);
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    const challenge = url.searchParams.get('code_challenge');
    expect(challenge).toBeTruthy();
    expect(challenge).toMatch(/^[A-Za-z0-9_-]+$/); // b64url, no padding
  });

  it('rejects redirectUri with wrong path', async () => {
    const slug = registerAuthCodeProvider();
    await expect(beginAuthCodeFlow(slug, 'https://dash.test/wrong/path'))
      .rejects.toMatchObject({ code: 'device_flow_error' });
    await expect(beginAuthCodeFlow(slug, 'ftp://dash.test/api/oauth/testauth/callback'))
      .rejects.toMatchObject({ code: 'device_flow_error' });
  });

  it('rejects device-flow provider slug', async () => {
    const slug = registerTestProvider('testoauth2');
    await expect(beginAuthCodeFlow(slug, REDIRECT))
      .rejects.toMatchObject({ code: 'device_flow_unsupported' });
  });

  it('callback happy path: exchanges code, enriches, returns credential', async () => {
    const slug = registerAuthCodeProvider();
    const start = await beginAuthCodeFlow(slug, REDIRECT);
    const fetchMock = vi.fn().mockResolvedValueOnce(jsonResponse({
      access_token: 'ac-at',
      refresh_token: 'ac-rt',
      expires_in: 3600,
      token_type: 'Bearer',
    }));
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const result = await handleAuthCodeCallback(slug, 'auth-code-1', start.flowId, REDIRECT);
    expect(result.status).toBe('ok');
    if (result.status === 'ok') {
      expect(result.credential.access_token).toBe('ac-at');
      expect(result.credential.refresh_token).toBe('ac-rt');
      expect(result.credential.provider).toBe(slug);
      expect(result.credential.project_id).toBe('proj-test'); // enrich ran
    }
    // Token exchange carried the PKCE verifier + redirect_uri.
    const body = String((fetchMock.mock.calls[0][1] as RequestInit).body);
    expect(body).toContain('grant_type=authorization_code');
    expect(body).toContain('code=auth-code-1');
    expect(body).toContain('code_verifier=');
    expect(body).toContain(`redirect_uri=${encodeURIComponent(REDIRECT)}`);
    expect(body).toContain('client_secret=auth-secret');
  });

  it('unknown state → expired', async () => {
    const slug = registerAuthCodeProvider();
    const result = await handleAuthCodeCallback(slug, 'c', 'ac_nonexistent', REDIRECT);
    expect(result.status).toBe('expired');
  });

  it('state is single-use: second callback → expired', async () => {
    const slug = registerAuthCodeProvider();
    const start = await beginAuthCodeFlow(slug, REDIRECT);
    globalThis.fetch = vi.fn().mockResolvedValue(jsonResponse({
      access_token: 'a', refresh_token: 'r', expires_in: 60,
    })) as unknown as typeof fetch;

    const first = await handleAuthCodeCallback(slug, 'code', start.flowId, REDIRECT);
    expect(first.status).toBe('ok');
    const second = await handleAuthCodeCallback(slug, 'code', start.flowId, REDIRECT);
    expect(second.status).toBe('expired');
  });

  it('expired flow (TTL) → expired', async () => {
    const slug = registerAuthCodeProvider();
    const start = await beginAuthCodeFlow(slug, REDIRECT);
    const realNow = Date.now();
    const spy = vi.spyOn(Date, 'now').mockReturnValue(realNow + 11 * 60 * 1000);
    try {
      const result = await handleAuthCodeCallback(slug, 'code', start.flowId, REDIRECT);
      expect(result.status).toBe('expired');
    } finally {
      spy.mockRestore();
    }
  });

  it('redirect_uri mismatch → error and flow consumed', async () => {
    const slug = registerAuthCodeProvider();
    const start = await beginAuthCodeFlow(slug, REDIRECT);
    const result = await handleAuthCodeCallback(
      slug, 'code', start.flowId, 'https://evil.test/api/oauth/testauth/callback');
    expect(result.status).toBe('error');
    // Flow deleted on failure — retry reads as expired.
    const again = await handleAuthCodeCallback(slug, 'code', start.flowId, REDIRECT);
    expect(again.status).toBe('expired');
  });

  it('token endpoint error → error status', async () => {
    const slug = registerAuthCodeProvider('testauth2');
    const start = await beginAuthCodeFlow(slug, 'https://dash.test/api/oauth/testauth2/callback');
    globalThis.fetch = vi.fn().mockResolvedValueOnce(jsonResponse({
      error: 'invalid_grant', error_description: 'Bad code',
    }, 400)) as unknown as typeof fetch;
    const result = await handleAuthCodeCallback(slug, 'bad', start.flowId, 'https://dash.test/api/oauth/testauth2/callback');
    expect(result.status).toBe('error');
    if (result.status === 'error') expect(result.message).toContain('Bad code');
  });
});
