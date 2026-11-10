// OAuth2 credential contract for providers whose "API key" is actually a
// token set (access + refresh) instead of a static bearer string — Antigravity
// (Google Cloud Code Assist), Devin, and future OAuth-onboarded providers.
//
// STORAGE SHAPE
// ---------------
// An OAuth api_keys row keeps using the existing encrypted_key/iv/auth_tag
// columns. The PLAINTEXT inside that AES-GCM blob is a JSON document:
//
//   {
//     "v": 1,
//     "provider": "antigravity",
//     "access_token": "ya29....",
//     "refresh_token": "1//0g...",
//     "expires_at": 1730000000000,        // epoch ms
//     "email": "user@gmail.com",          // optional account label
//     "project_id": "cloud-....",         // provider extras, opaque here
//     ...
//   }
//
// Non-secret bookkeeping (provider slug, expiry, email) is ALSO mirrored into
// api_keys.oauth_provider / oauth_expires_at / oauth_email so the dashboard and
// health checker can see token state without decrypting. The refresh token
// lives ONLY inside the encrypted blob — never in a plaintext column.
//
// REFRESH PATH
// ------------
// Provider adapters receive the decrypted JSON string as their `apiKey`
// argument. `getValidAccessToken(apiKeyJson, keyRow)` returns a live access
// token, refreshing + persisting the blob when it is inside the refresh
// margin. Providers call it at the top of every request — the common case is
// a pure parse, no I/O.
//
// The refresh itself goes through lib/oauth.ts's provider registry
// (beginDeviceFlow / refreshAccessToken); this file owns only the blob
// contract so it stays importable from routes, router, and providers without
// pulling in fetch logic.

import { getDb } from '../db/index.js';
import { encrypt } from './crypto.js';

/** Refresh this far before the recorded expiry so an in-flight request never
 *  races the token's death. */
export const OAUTH_REFRESH_MARGIN_MS = 60_000;

export interface OAuthCredential {
  v: 1;
  /** Registry slug matching lib/oauth.ts OAUTH_PROVIDERS ('antigravity', ...). */
  provider: string;
  access_token: string;
  /** Absent for providers that don't issue one (rare; device flow always does). */
  refresh_token?: string;
  /** Epoch ms when access_token stops being accepted. */
  expires_at: number;
  /** Optional account label mirrored to api_keys.oauth_email. */
  email?: string;
  /** Provider-specific extras (antigravity: project_id, tier). */
  [extra: string]: unknown;
}

/** Parse an api_keys.encrypted_key plaintext as an OAuth credential blob.
 *  Returns null for static keys (non-JSON, or JSON without the marker shape). */
export function parseOAuthCredential(apiKeyPlaintext: string): OAuthCredential | null {
  const trimmed = apiKeyPlaintext.trim();
  if (!trimmed.startsWith('{')) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    return null;
  }
  if (typeof parsed !== 'object' || parsed === null) return null;
  const obj = parsed as Record<string, unknown>;
  if (obj.v !== 1) return null;
  if (typeof obj.provider !== 'string' || !obj.provider) return null;
  if (typeof obj.access_token !== 'string' || !obj.access_token) return null;
  if (typeof obj.expires_at !== 'number') return null;
  return obj as OAuthCredential;
}

/** True when the credential's access token needs a refresh (expired or inside
 *  the safety margin). Credentials without a refresh_token are never
 *  refreshable — they report false so callers surface them as dead keys. */
export function oauthCredentialNeedsRefresh(cred: OAuthCredential, now = Date.now()): boolean {
  if (!cred.refresh_token) return false;
  return cred.expires_at - OAUTH_REFRESH_MARGIN_MS <= now;
}

/** Serialize a credential back into the api_keys.encrypted_key plaintext
 *  shape. Mirrors the bookkeeping columns so a refresh keeps them in sync. */
export function serializeOAuthCredential(cred: OAuthCredential): string {
  return JSON.stringify(cred);
}

/** Persist a refreshed credential onto the api_keys row: re-encrypts the JSON
 *  blob into encrypted_key/iv/auth_tag and updates the bookkeeping columns.
 *  Returns the new plaintext blob (what the provider should use next). */
export function persistOAuthCredential(keyId: number, cred: OAuthCredential): string {
  const plaintext = serializeOAuthCredential(cred);
  const { encrypted, iv, authTag } = encrypt(plaintext);
  getDb().prepare(`
    UPDATE api_keys
       SET encrypted_key = ?, iv = ?, auth_tag = ?,
           oauth_expires_at = ?, oauth_email = COALESCE(?, oauth_email)
     WHERE id = ?
  `).run(encrypted, iv, authTag, cred.expires_at, cred.email ?? null, keyId);
  return plaintext;
}
