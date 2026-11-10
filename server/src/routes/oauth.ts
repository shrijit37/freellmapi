// OAuth2 enrollment API — device-flow sign-in for OAuth-backed providers
// (Antigravity today; the registry in lib/oauth.ts accepts more).
//
//   GET    /api/oauth/providers          list registrable providers
//   POST   /api/oauth/:provider/device   begin RFC 8628 device flow
//   GET    /api/oauth/device/:flowId     poll status; on 'complete' the
//                                        credential is encrypted into a new
//                                        api_keys row (oauth_* columns set)
//   DELETE /api/oauth/device/:flowId     cancel an in-flight flow
//
// Mounted under /api with requireAuth like every other dashboard route —
// enrollment mints a working provider credential, so it must not be reachable
// with the unified /v1 inference key.
//
// KEY INSERTION
// -------------
// Completion inserts into api_keys directly rather than going through
// routes/keys.ts: OAuth rows carry provider/expiry/email bookkeeping columns
// and an encrypted JSON blob instead of a static key, so the generic add-key
// schema does not apply. The INSERT mirrors insertImportedKey's minimal
// column set (platform, label, encrypted_key, iv, auth_tag, status,
// enabled) plus the oauth_* bookkeeping columns.

import { Router } from 'express';
import type { Request, Response } from 'express';
import { z } from 'zod';
import { getDb } from '../db/index.js';
import { encrypt } from '../lib/crypto.js';
import { serializeOAuthCredential, type OAuthCredential } from '../lib/oauth-credentials.js';
import {
  OAUTH_PROVIDERS,
  OAuthError,
  beginAuthCodeFlow,
  beginDeviceFlow,
  cancelDeviceFlow,
  getDeviceFlowStatus,
  handleAuthCodeCallback,
} from '../lib/oauth.js';

export const oauthRouter = Router();

// GET /api/oauth/providers — list registrable providers and their flow type.
oauthRouter.get('/providers', (_req: Request, res: Response) => {
  const providers = Object.values(OAUTH_PROVIDERS).map(p => ({
    slug: p.slug,
    displayName: p.displayName,
    flow: p.flow ?? 'device',
  }));
  res.json({ providers });
});

const providerParamSchema = z.string().min(1).max(64);

// POST /api/oauth/:provider/device — kick off a device authorization flow.
// Authcode providers are rejected here; they enroll via /:provider/authcode
// + the public /:provider/callback.
oauthRouter.post('/:provider/device', async (req: Request, res: Response) => {
  const parsed = providerParamSchema.safeParse(req.params.provider);
  if (!parsed.success) {
    res.status(400).json({ error: { message: 'Invalid provider slug' } });
    return;
  }
  const provider = OAUTH_PROVIDERS[parsed.data];
  if (provider && (provider.flow ?? 'device') === 'authcode') {
    res.status(400).json({
      error: { message: `Provider '${parsed.data}' uses the authcode flow`, code: 'wrong_flow', type: 'wrong_flow' },
    });
    return;
  }
  try {
    const start = await beginDeviceFlow(parsed.data);
    res.status(201).json(start);
  } catch (err) {
    if (err instanceof OAuthError) {
      const status = err.code === 'unknown_provider' ? 404 : 502;
      res.status(status).json({ error: { message: err.message, code: err.code } });
      return;
    }
    res.status(502).json({ error: { message: (err as Error).message } });
  }
});

const authCodeStartSchema = z.object({
  redirectUri: z.string().url().max(2048),
});

// POST /api/oauth/:provider/authcode — start an authorization-code + PKCE
// flow. Returns {flowId, authUrl}; the dashboard opens authUrl in the
// user's browser. The provider redirects back to GET
// /api/oauth/:provider/callback (public — see oauthPublicRouter below).
oauthRouter.post('/:provider/authcode', async (req: Request, res: Response) => {
  const parsedProvider = providerParamSchema.safeParse(req.params.provider);
  const parsedBody = authCodeStartSchema.safeParse(req.body);
  if (!parsedProvider.success || !parsedBody.success) {
    res.status(400).json({
      error: { message: !parsedProvider.success ? 'Invalid provider slug' : 'Body must be { redirectUri: string }' },
    });
    return;
  }
  try {
    const start = await beginAuthCodeFlow(parsedProvider.data, parsedBody.data.redirectUri);
    res.status(201).json(start);
  } catch (err) {
    if (err instanceof OAuthError) {
      const status = err.code === 'unknown_provider' ? 404 : 400;
      res.status(status).json({ error: { message: err.message, code: err.code } });
      return;
    }
    res.status(502).json({ error: { message: (err as Error).message } });
  }
});

// INSERT the enrolled credential as an api_keys row. Exported for tests.
export function insertOAuthKey(cred: OAuthCredential, providerDisplayName: string): number {
  const db = getDb();
  const plaintext = serializeOAuthCredential(cred);
  const { encrypted, iv, authTag } = encrypt(plaintext);
  const label = cred.email ?? `${providerDisplayName} OAuth`;
  const result = db.prepare(`
    INSERT INTO api_keys (platform, label, encrypted_key, iv, auth_tag, status, enabled, oauth_provider, oauth_expires_at, oauth_email)
    VALUES (?, ?, ?, ?, ?, 'unknown', 1, ?, ?, ?)
  `).run(
    cred.provider,
    label,
    encrypted,
    iv,
    authTag,
    cred.provider,
    cred.expires_at,
    cred.email ?? null,
  );
  return Number(result.lastInsertRowid);
}

// GET /api/oauth/device/:flowId — poll the flow. On 'complete' the credential
// becomes an api_keys row exactly once (subsequent polls hit the in-memory
// sticky 'complete' outcome and would re-insert — so we track issued flows).
const completedFlows = new Set<string>();

oauthRouter.get('/device/:flowId', async (req: Request, res: Response) => {
  const flowId = String(req.params.flowId ?? '');
  if (!flowId || flowId.length > 128) {
    res.status(400).json({ error: { message: 'Invalid flow id' } });
    return;
  }
  try {
    const status = await getDeviceFlowStatus(flowId);
    if (status.status === 'complete') {
      // Idempotent completion: the first poll that sees 'complete' creates the
      // key; later polls return the same keyId instead of duplicating rows.
      if (completedFlows.has(flowId)) {
        res.json({ status: 'complete', alreadyEnrolled: true });
        return;
      }
      const provider = OAUTH_PROVIDERS[status.credential.provider];
      const displayName = provider?.displayName ?? status.credential.provider;
      const keyId = insertOAuthKey(status.credential, displayName);
      completedFlows.add(flowId);
      res.json({ status: 'complete', keyId });
      return;
    }
    if (status.status === 'error') {
      res.json({ status: 'error', message: status.message });
      return;
    }
    res.json(status); // 'pending' | 'expired'
  } catch (err) {
    res.status(500).json({ error: { message: (err as Error).message } });
  }
});

// DELETE /api/oauth/device/:flowId — abandon an in-flight flow.
oauthRouter.delete('/device/:flowId', (req: Request, res: Response) => {
  const flowId = String(req.params.flowId ?? '');
  cancelDeviceFlow(flowId);
  completedFlows.delete(flowId);
  res.json({ status: 'cancelled' });
});

// ---------------------------------------------------------------------------
// PUBLIC authcode callback — the OAuth provider redirects the USER'S BROWSER
// here, so this route must NOT sit behind requireAuth (no dashboard session
// exists in that browser context). It is mounted separately as
// oauthPublicRouter in app.ts BEFORE the authed /api/oauth mount.
// ---------------------------------------------------------------------------

function htmlPage(title: string, body: string, status: number): { html: string; status: number } {
  return {
    status,
    html: `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title></head>` +
      `<body style="font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;text-align:center">` +
      `<h2>${title}</h2><p>${body}</p></body></html>`,
  };
}

export const oauthPublicRouter = Router();

// GET /api/oauth/:provider/callback?code=…&state=… — the redirect target.
// `state` is the flowId minted by beginAuthCodeFlow; `error` carries provider
// denials (access_denied etc.). The redirect_uri must match the one the flow
// was begun with — reconstructed from the request's own origin+path, which is
// exactly what the dashboard passed as redirectUri.
oauthPublicRouter.get('/:provider/callback', async (req: Request, res: Response) => {
  const providerSlug = String(req.params.provider ?? '');
  const provider = OAUTH_PROVIDERS[providerSlug];
  if (!provider || (provider.flow ?? 'device') !== 'authcode') {
    const page = htmlPage('Unknown provider', 'This OAuth callback does not match a registered provider.', 404);
    res.status(page.status).type('html').send(page.html);
    return;
  }

  const errorParam = typeof req.query.error === 'string' ? req.query.error : '';
  const code = typeof req.query.code === 'string' ? req.query.code : '';
  const state = typeof req.query.state === 'string' ? req.query.state : '';

  if (errorParam) {
    const desc = typeof req.query.error_description === 'string' ? req.query.error_description : errorParam;
    const page = htmlPage('Authorization failed', `The provider returned: ${desc}`, 400);
    res.status(page.status).type('html').send(page.html);
    return;
  }
  if (!code || !state) {
    const page = htmlPage('Missing parameters', 'The callback is missing code or state.', 400);
    res.status(page.status).type('html').send(page.html);
    return;
  }

  // Reconstruct the redirect_uri the flow was started with: scheme + host +
  // this route's own path. Proxied/forwarded setups must preserve the public
  // origin (X-Forwarded-* handled by Express trust-proxy settings upstream).
  const redirectUri = `${req.protocol}://${req.get('host')}${req.baseUrl}${req.path}`;

  try {
    const completion = await handleAuthCodeCallback(providerSlug, code, state, redirectUri);
    if (completion.status === 'ok') {
      const keyId = insertOAuthKey(completion.credential, provider.displayName);
      const page = htmlPage(
        'Account linked',
        `FreeLLMAPI: account linked (key #${keyId}) — you can close this tab.`,
        200,
      );
      res.status(page.status).type('html').send(page.html);
      return;
    }
    if (completion.status === 'expired') {
      const page = htmlPage('Flow expired', 'This sign-in link expired or was already used. Start again from the dashboard.', 400);
      res.status(page.status).type('html').send(page.html);
      return;
    }
    const message = completion.status === 'error' ? completion.message : 'Authorization did not complete';
    const page = htmlPage('Authorization failed', message, 400);
    res.status(page.status).type('html').send(page.html);
  } catch (err) {
    const page = htmlPage('Authorization failed', (err as Error).message, 500);
    res.status(page.status).type('html').send(page.html);
  }
});

