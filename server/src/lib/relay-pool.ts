// Egress relay pool — pi-freeflow-compatible HTTPS relay endpoints.
//
// A relay worker is a tiny edge function (Cloudflare Worker / Vercel / Deno)
// that forwards one upstream API request from its own egress IP. FreeLLMAPI
// sends the upstream request to the relay with three control headers:
//
//   Host:             <host of the upstream URL>
//   x-relay-target:   <full upstream URL>
//   x-relay-path:     <path + query of the upstream URL>
//   x-relay-auth:     <per-relay shared secret, only when configured>
//
// and the relay fetches the target from its own IP and streams the response
// back untouched. Pools group entries so several exits can serve one key;
// round-robin rotates across healthy entries, sticky pins one entry per key
// until it fails, and cooldowns keep broken exits out of rotation.
//
// Selection, health tracking and the wire protocol all live here; the CRUD
// surface for pools/entries is lib/relays.ts and the egress dispatch hook is
// lib/proxy.ts (dispatchFetch resolves the request-scoped pool from the
// AsyncLocalStorage egress context set by withRequestEgress).
//
// Cooldown policy: consecutive_failures feeds an exponential backoff,
// cooldown = min(2^n * 5s, 10min). A success clears the streak and the
// cooldown; last_status / last_error / ewma_latency_ms stay as diagnostics.

import { getDb } from '../db/index.js';
import { decrypt } from './crypto.js';
import { classifyIp, isLoopbackOrPrivateHostname } from './url-guard.js';
import net from 'node:net';

// ── Types ────────────────────────────────────────────────────────────────────

export type RelayPoolMode = 'round-robin' | 'sticky';
export type RelayPoolFallback = 'direct' | 'fail';
export type RelayMode = 'inherit' | 'pool' | 'direct';

export interface RelayPool {
  id: number;
  name: string;
  description: string;
  is_default: number;
  enabled: number;
  mode: RelayPoolMode;
  fallback: RelayPoolFallback;
  created_at: string;
  updated_at: string;
}

/** An entry row as stored. auth_encrypted/auth_iv/auth_auth_tag are the
 *  AES-GCM columns holding the shared secret (empty string secret = NULLs). */
export interface RelayPoolEntry {
  id: number;
  pool_id: number;
  url: string;
  label: string;
  auth_encrypted: string | null;
  auth_iv: string | null;
  auth_auth_tag: string | null;
  enabled: number;
  cooldown_until: string | null;
  last_status: number | null;
  last_error: string | null;
  consecutive_failures: number;
  ewma_latency_ms: number | null;
  created_at: string;
  updated_at: string;
}

/** Entry with the auth secret already decrypted — what selection works on. */
interface LiveEntry {
  id: number;
  poolId: number;
  url: string;
  relayUrl: URL;
  auth: string;
}

export class RelayExhaustedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RelayExhaustedError';
  }
}

// ── Constants ────────────────────────────────────────────────────────────────

// Per-attempt timeout for the request to the RELAY hop. The relay itself may
// stream a long upstream SSE body, so this only bounds time-to-first-byte
// style stalls: fetch's AbortSignal covers the whole exchange, which is why
// long streams need the caller's own signal merged in (relayFetch does that).
const RELAY_ATTEMPT_TIMEOUT_MS = 30_000;

// Backoff: min(2^failures * 5s, 10min). failures>=1 on the first mark.
const COOLDOWN_BASE_MS = 5_000;
const COOLDOWN_MAX_MS = 10 * 60_000;

// EWMA weight for a fresh latency sample (0..1): older samples decay.
const EWMA_ALPHA = 0.3;

// How many entries a single request may roll through before the pool is
// declared exhausted. Bounded so a big pool of dead relays can't multiply
// latency without limit.
const MAX_ROLLS_PER_REQUEST = 4;

// Statuses that mean "the RELAY failed", not "the upstream answered".
// A forwarded upstream 401 reaches us as a 401 too — the worker's own
// rejection body is what separates them (see isRelayAuthRejection).
const RELAY_FAIL_STATUSES = new Set([429, 500, 502, 503, 504]);

// The pi-freeflow worker answers an unauthenticated/bad-secret request with
// a small JSON error body rather than passing it through. Matching the shape
// (not just the status) is what keeps a genuine upstream credential failure —
// which the relay forwards as-is — from benching a healthy relay.
const RELAY_AUTH_REJECTION_RE = /"unauthorized"|"forbidden"|"invalid[_ -]?token"|"authentication/i;

// ── SSRF / URL validation ────────────────────────────────────────────────────

export interface RelayUrlVerdict {
  ok: boolean;
  reason?: string;
}

/**
 * Validate a relay base URL for storage and for request-time use.
 *
 * Policy (stricter than the custom-provider guard, because a relay URL is
 * stored by an operator and contacted on EVERY proxied request):
 *  - https only — the hop carries provider credentials, so plaintext http is
 *    only tolerable on loopback, which is refused anyway here.
 *  - No credentials embedded in the URL (`user:pass@`).
 *  - Host must be a public address: loopback, RFC1918/ULA, CGNAT, link-local,
 *    and cloud-metadata hosts are all rejected. Literal IPs are classified
 *    synchronously; hostnames are checked by name pattern (localhost etc.) —
 *    DNS is resolved once at add-time in relays.ts via assessProviderUrl for
 *    the write path, and again cheaply here for obvious literals.
 */
export function validateRelayUrl(rawUrl: string): RelayUrlVerdict {
  let url: URL;
  try {
    url = new URL(rawUrl.trim());
  } catch {
    return { ok: false, reason: 'not a valid URL' };
  }
  if (url.protocol !== 'https:') {
    return { ok: false, reason: 'relay URLs must use https://' };
  }
  if (url.username || url.password) {
    return { ok: false, reason: 'credentials in the relay URL are not allowed; use the auth field' };
  }
  const hostname = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (!hostname) return { ok: false, reason: 'missing host' };
  if (isLoopbackOrPrivateHostname(hostname)) {
    return { ok: false, reason: 'relay host must be a public address (loopback/private ranges are not allowed)' };
  }
  if (net.isIP(hostname)) {
    const cls = classifyIp(hostname);
    if (cls !== 'public') {
      return { ok: false, reason: `relay host ${hostname} is a ${cls} address` };
    }
  }
  // Metadata hostnames that resolve by name rather than literal.
  if (hostname === 'metadata.google.internal' || hostname.endsWith('.internal')) {
    return { ok: false, reason: 'relay host is a reserved/internal name' };
  }
  return { ok: true };
}

/**
 * SSRF check for the x-relay-target value — the upstream URL being relayed.
 * Provider base URLs are operator-configured too, but a relay pool must not
 * become a confused deputy: refuse to forward to private/metadata targets
 * through a relay just as proxyFetch refuses them direct.
 */
export function validateRelayTarget(rawUrl: string): RelayUrlVerdict {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return { ok: false, reason: 'not a valid URL' };
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    return { ok: false, reason: `unsupported protocol ${url.protocol}` };
  }
  const hostname = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (isLoopbackOrPrivateHostname(hostname)) {
    return { ok: false, reason: 'relay target must be a public address' };
  }
  if (net.isIP(hostname)) {
    const cls = classifyIp(hostname);
    if (cls === 'metadata' || cls === 'link-local') {
      return { ok: false, reason: `relay target ${hostname} is a ${cls} address` };
    }
  }
  return { ok: true };
}

// ── DB access ────────────────────────────────────────────────────────────────

function decryptEntryAuth(row: RelayPoolEntry): string {
  if (!row.auth_encrypted || !row.auth_iv || !row.auth_auth_tag) return '';
  try {
    return decrypt(row.auth_encrypted, row.auth_iv, row.auth_auth_tag);
  } catch {
    return '';
  }
}

function toLiveEntry(row: RelayPoolEntry): LiveEntry | null {
  const verdict = validateRelayUrl(row.url);
  if (!verdict.ok) return null;
  let relayUrl: URL;
  try {
    relayUrl = new URL(row.url);
  } catch {
    return null;
  }
  return {
    id: row.id,
    poolId: row.pool_id,
    url: row.url,
    relayUrl,
    auth: decryptEntryAuth(row),
  };
}

function loadPool(poolId: number): RelayPool | undefined {
  return getDb().prepare('SELECT * FROM relay_pools WHERE id = ?').get(poolId) as RelayPool | undefined;
}

function loadEntries(poolId: number): RelayPoolEntry[] {
  return getDb().prepare(
    'SELECT * FROM relay_pool_entries WHERE pool_id = ? ORDER BY id',
  ).all(poolId) as RelayPoolEntry[];
}

function loadDefaultPool(): RelayPool | undefined {
  return getDb().prepare(
    'SELECT * FROM relay_pools WHERE is_default = 1 AND enabled = 1 LIMIT 1',
  ).get() as RelayPool | undefined;
}

/** Resolve which pool an api_keys egress setting points at. */
export function resolvePoolForKey(relayMode: string | null | undefined, relayPoolId: number | null | undefined): RelayPool | undefined {
  if (relayMode === 'direct') return undefined;
  if (relayMode === 'pool') {
    if (relayPoolId != null) {
      const pool = loadPool(relayPoolId);
      return pool && pool.enabled ? pool : undefined;
    }
    return loadDefaultPool();
  }
  // 'inherit' or unset → default pool.
  return loadDefaultPool();
}

// ── Selection state ──────────────────────────────────────────────────────────

// Round-robin cursor per pool: in-memory only, resets on restart (fine —
// rotation order is not a correctness property).
const rrCursor = new Map<number, number>();

// Sticky pins: pool+key scope → entry id. 'sticky' mode pins one relay per
// (pool, api key or request scope); a pin is dropped when the entry fails so
// the next request re-picks.
const stickyPins = new Map<string, number>();

function stickyKey(poolId: number, scope?: string | number): string {
  return `${poolId}:${scope ?? 'default'}`;
}

function entryIsHealthy(row: RelayPoolEntry, now: number): boolean {
  if (!row.enabled) return false;
  if (row.cooldown_until) {
    const until = Date.parse(row.cooldown_until.includes('T') ? row.cooldown_until : row.cooldown_until.replace(' ', 'T') + 'Z');
    if (Number.isFinite(until) && until > now) return false;
  }
  return true;
}

interface PoolSelection {
  pool: RelayPool;
  /** Ordered live entries to try, already filtered to enabled+not-cooling. */
  entries: LiveEntry[];
}

function selectFromPool(pool: RelayPool, scope?: string | number): PoolSelection | null {
  const rows = loadEntries(pool.id);
  const now = Date.now();
  const healthy = rows.filter(r => entryIsHealthy(r, now));
  const live = healthy.map(toLiveEntry).filter((e): e is LiveEntry => e !== null);
  if (live.length === 0) return null;

  if (pool.mode === 'sticky') {
    const pin = stickyPins.get(stickyKey(pool.id, scope));
    if (pin != null) {
      const pinned = live.find(e => e.id === pin);
      if (pinned) {
        // Pinned entry first; remaining healthy entries still follow as
        // failover within this request.
        return { pool, entries: [pinned, ...live.filter(e => e.id !== pinned.id)] };
      }
      stickyPins.delete(stickyKey(pool.id, scope));
    }
    // No pin yet: pick the round-robin head and pin it.
    const head = live[(rrCursor.get(pool.id) ?? 0) % live.length] ?? live[0];
    const headIndex = live.indexOf(head);
    rrCursor.set(pool.id, ((headIndex >= 0 ? headIndex : 0) + 1) % live.length);
    stickyPins.set(stickyKey(pool.id, scope), head.id);
    return { pool, entries: [head, ...live.filter(e => e.id !== head.id)] };
  }

  // round-robin
  const cursor = rrCursor.get(pool.id) ?? 0;
  const ordered = [...live.slice(cursor % live.length), ...live.slice(0, cursor % live.length)];
  rrCursor.set(pool.id, (cursor + 1) % live.length);
  return { pool, entries: ordered };
}

// ── Health bookkeeping ───────────────────────────────────────────────────────

function cooldownMsFor(failures: number): number {
  // failures is the NEW consecutive_failures count (>=1).
  const exp = Math.min(COOLDOWN_BASE_MS * 2 ** Math.max(0, failures - 1), COOLDOWN_MAX_MS);
  return exp;
}

function markRelayResult(entryId: number, ok: boolean, status: number | null, error: string | null, latencyMs: number): void {
  const db = getDb();
  const row = db.prepare('SELECT consecutive_failures FROM relay_pool_entries WHERE id = ?').get(entryId) as { consecutive_failures: number } | undefined;
  if (!row) return;
  if (ok) {
    db.prepare(`
      UPDATE relay_pool_entries
         SET consecutive_failures = 0,
             cooldown_until = NULL,
             last_status = ?,
             last_error = NULL,
             ewma_latency_ms = ?,
             updated_at = datetime('now')
       WHERE id = ?
    `).run(status, latencyMs, entryId);
    return;
  }
  const failures = row.consecutive_failures + 1;
  const cooldownMs = cooldownMsFor(failures);
  const until = new Date(Date.now() + cooldownMs).toISOString().replace('T', ' ').slice(0, 19);
  db.prepare(`
    UPDATE relay_pool_entries
       SET consecutive_failures = ?,
           cooldown_until = ?,
           last_status = ?,
           last_error = ?,
           updated_at = datetime('now')
     WHERE id = ?
  `).run(failures, until, status, error ? error.slice(0, 500) : null, entryId);
  // A failed pinned entry loses its pin so the next request re-selects.
  for (const [k, v] of stickyPins) {
    if (v === entryId) stickyPins.delete(k);
  }
}

// ── Wire protocol ────────────────────────────────────────────────────────────

/** Build the request to the relay worker for upstream `targetUrl`.
 *  Exported for tests. */
export function buildRelayRequest(relayBase: URL, targetUrl: string, init: RequestInit | undefined, auth: string): { url: string; init: RequestInit } {
  const target = new URL(targetUrl);
  const relayUrl = new URL(relayBase.toString());
  // The worker serves the same path+query as the upstream; x-relay-path
  // carries the exact path+query for workers that route on it.
  relayUrl.pathname = target.pathname;
  relayUrl.search = target.search;

  const headers = new Headers(init?.headers);
  // These describe the upstream connection; the relay hop recomputes them.
  headers.delete('host');
  headers.delete('content-length');
  headers.delete('connection');
  headers.delete('keep-alive');
  headers.delete('transfer-encoding');
  headers.delete('te');
  headers.delete('trailer');
  headers.delete('upgrade');
  headers.set('x-relay-target', targetUrl);
  headers.set('x-relay-path', target.pathname + target.search);
  // Host header = upstream host. Fetch forbids setting Host directly in
  // browsers but undici/Node allows it via the headers object on http(s)
  // requests — for the relay hop it is REQUIRED by the pi-freeflow protocol
  // (the worker uses it for routing/logging). undici honours an explicit
  // host header.
  headers.set('host', target.host);
  if (auth) headers.set('x-relay-auth', auth);
  else headers.delete('x-relay-auth');

  return { url: relayUrl.toString(), init: { ...init, headers, redirect: 'manual' } };
}

/** True when a response from the RELAY is the worker's own auth rejection
 *  rather than a forwarded upstream response. Only meaningful for 401/403. */
async function isRelayAuthRejection(response: Response): Promise<boolean> {
  if (response.status !== 401 && response.status !== 403) return false;
  try {
    const clone = response.clone();
    const text = await clone.text();
    // The worker's rejection is a small JSON error; a forwarded upstream 401
    // (e.g. a revoked provider key) usually carries a larger provider-specific
    // body. Shape-match on the error marker, size-capped for safety.
    if (text.length > 8192) return false;
    return RELAY_AUTH_REJECTION_RE.test(text);
  } catch {
    return false;
  }
}

function shouldFailover(status: number, relayAuthRejection: boolean): boolean {
  if (relayAuthRejection) return true; // 401/403 that is the WORKER rejecting us
  if (RELAY_FAIL_STATUSES.has(status)) return true;
  // Bare 403 from the relay is always suspect per the contract ("always cool
  // on 403") — but only when it isn't clearly an upstream answer. Without a
  // body we can't tell; the contract says treat relay 403 as failure.
  if (status === 403) return true;
  return false;
}

export interface RelayFetchOptions {
  /** Pin scope for sticky pools — the api key id or a request-scoped token. */
  stickyScope?: string | number;
  /** Caller abort signal, merged into each attempt's timeout. */
  signal?: AbortSignal;
  /** Max entries to roll through; defaults to MAX_ROLLS_PER_REQUEST. */
  maxRolls?: number;
}

export type RelayFetchResult =
  | { ok: true; response: Response }
  | { ok: false; reason: 'exhausted' | 'no-pool' | 'blocked-target'; message: string };

/**
 * Send `init` to `targetUrl` through the resolved relay pool.
 *
 * Returns {ok:true, response} with the upstream response passed through
 * untouched (including its status — a 429 from the UPSTREAM is a successful
 * relay exchange and does NOT cool the relay; only relay-side failures do).
 * Returns {ok:false} when no pool resolves, the target fails SSRF, or every
 * candidate entry failed — the caller then applies the pool's fallback
 * policy ('direct' → continue to global path, 'fail' → RelayExhaustedError).
 */
export async function relayFetch(
  pool: RelayPool | undefined,
  targetUrl: string,
  init: RequestInit | undefined,
  opts: RelayFetchOptions = {},
): Promise<RelayFetchResult> {
  if (!pool) return { ok: false, reason: 'no-pool', message: 'no relay pool resolved' };

  const targetVerdict = validateRelayTarget(targetUrl);
  if (!targetVerdict.ok) {
    return { ok: false, reason: 'blocked-target', message: `relay target rejected: ${targetVerdict.reason}` };
  }

  const selection = selectFromPool(pool, opts.stickyScope);
  if (!selection) {
    return { ok: false, reason: 'exhausted', message: `relay pool "${pool.name}" has no healthy entries` };
  }

  const maxRolls = Math.min(opts.maxRolls ?? MAX_ROLLS_PER_REQUEST, selection.entries.length);
  let lastError: string | null = null;

  for (let i = 0; i < maxRolls; i++) {
    const entry = selection.entries[i];
    const { url: relayUrl, init: relayInit } = buildRelayRequest(entry.relayUrl, targetUrl, init, entry.auth);

    // Merge the caller's signal with a per-attempt timeout. Body streams are
    // bounded by the caller's own timeout/abort upstream — the 30s here only
    // guards the relay hop stalling before headers.
    const timeout = AbortSignal.timeout(RELAY_ATTEMPT_TIMEOUT_MS);
    const signal = opts.signal ? AbortSignal.any([opts.signal, timeout]) : timeout;

    const startedAt = Date.now();
    let response: Response;
    try {
      response = await fetch(relayUrl, { ...relayInit, signal });
    } catch (err) {
      lastError = err instanceof Error ? err.message : String(err);
      markRelayResult(entry.id, false, null, lastError, Date.now() - startedAt);
      continue;
    }

    const latencyMs = Date.now() - startedAt;
    const authRejection = await isRelayAuthRejection(response);
    if (shouldFailover(response.status, authRejection)) {
      // Drain a little of the body so the socket is reusable; clone keeps it.
      lastError = `relay ${entry.id} responded ${response.status}${authRejection ? ' (auth rejection)' : ''}`;
      markRelayResult(entry.id, false, response.status, lastError, latencyMs);
      continue;
    }

    // 2xx/3xx/4xx-that-is-upstream: the relay did its job. A forwarded
    // upstream error is NOT a relay failure.
    markRelayResult(entry.id, true, response.status, null, latencyMs);
    return { ok: true, response };
  }

  return {
    ok: false,
    reason: 'exhausted',
    message: lastError
      ? `all relay entries failed (last: ${lastError})`
      : `all relay entries failed for pool "${pool.name}"`,
  };
}

/** Test probe for POST /api/relays/:id/entries/:entryId/test — sends a
 *  minimal request through the entry and reports status/latency. Does NOT
 *  touch cooldown state (a probe failure is information, not a verdict on
 *  the pool's rotation — actually it SHOULD count: a dead relay probed by
 *  the operator is exactly what cooldown is for). We record the result like
 *  a real attempt. */
export async function testRelayEntry(entry: RelayPoolEntry): Promise<{ ok: boolean; status: number | null; latencyMs: number; error?: string }> {
  const live = toLiveEntry(entry);
  if (!live) return { ok: false, status: null, latencyMs: 0, error: 'relay URL failed validation' };
  const startedAt = Date.now();
  try {
    // Probe the relay root with a HEAD-like GET; the worker answers 4xx for
    // missing target headers, which still proves reachability + auth.
    const res = await fetch(live.relayUrl.toString(), {
      method: 'GET',
      headers: live.auth ? { 'x-relay-auth': live.auth } : {},
      signal: AbortSignal.timeout(10_000),
      redirect: 'manual',
    });
    const latencyMs = Date.now() - startedAt;
    const ok = res.status < 500;
    markRelayResult(entry.id, ok, res.status, ok ? null : `probe status ${res.status}`, latencyMs);
    return { ok, status: res.status, latencyMs };
  } catch (err) {
    const latencyMs = Date.now() - startedAt;
    const message = err instanceof Error ? err.message : String(err);
    markRelayResult(entry.id, false, null, message, latencyMs);
    return { ok: false, status: null, latencyMs, error: message };
  }
}
