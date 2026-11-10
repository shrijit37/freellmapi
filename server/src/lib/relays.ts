// CRUD + presentation helpers for relay pools and their entries.
//
// The HTTP surface lives in routes/relays.ts; this module owns the DB writes
// (single-default enforcement, entry auth encryption, URL validation) so the
// route stays a thin zod+auth wrapper. Auth secrets are AES-GCM encrypted via
// lib/crypto.ts — same columns pattern as api_keys.proxy_encrypted.

import { getDb } from '../db/index.js';
import { encrypt, decrypt } from './crypto.js';
import { assessProviderUrl } from './url-guard.js';
import {
  validateRelayUrl,
  testRelayEntry,
  type RelayPool,
  type RelayPoolEntry,
  type RelayPoolFallback,
  type RelayPoolMode,
} from './relay-pool.js';

export interface RelayPoolWithEntries extends RelayPool {
  entries: RelayEntryView[];
}

/** Entry as the API returns it: health fields visible, auth masked to a
 *  boolean + last-4 so the dashboard can show "secret set" without the secret. */
export interface RelayEntryView {
  id: number;
  pool_id: number;
  url: string;
  label: string;
  has_auth: boolean;
  auth_hint: string;
  enabled: number;
  cooldown_until: string | null;
  last_status: number | null;
  last_error: string | null;
  consecutive_failures: number;
  ewma_latency_ms: number | null;
  created_at: string;
  updated_at: string;
}

function entryView(row: RelayPoolEntry, auth: string): RelayEntryView {
  return {
    id: row.id,
    pool_id: row.pool_id,
    url: row.url,
    label: row.label,
    has_auth: auth.length > 0,
    // Last 4 chars only — enough to tell two secrets apart, not enough to use.
    auth_hint: auth.length >= 4 ? auth.slice(-4) : auth.length > 0 ? '••••' : '',
    enabled: row.enabled,
    cooldown_until: row.cooldown_until,
    last_status: row.last_status,
    last_error: row.last_error,
    consecutive_failures: row.consecutive_failures,
    ewma_latency_ms: row.ewma_latency_ms,
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}
function decryptAuthForView(row: RelayPoolEntry): string {
  if (!row.auth_encrypted || !row.auth_iv || !row.auth_auth_tag) return '';
  try {
    return decrypt(row.auth_encrypted, row.auth_iv, row.auth_auth_tag);
  } catch {
    return '';
  }
}

// ── Validation ───────────────────────────────────────────────────────────────

/** Full write-path validation: shape (validateRelayUrl) + DNS resolution
 *  (assessProviderUrl with blockPrivate) so a hostname that resolves to a
 *  private/metadata address is refused at save time, not just at request time. */

export async function validateRelayEntryUrl(rawUrl: string): Promise<{ ok: boolean; reason?: string }> {
  const shape = validateRelayUrl(rawUrl);
  if (!shape.ok) return shape;
  const verdict = await assessProviderUrl(rawUrl, { blockPrivate: true });
  if (!verdict.allowed) return { ok: false, reason: verdict.reason ?? 'relay URL resolves to a blocked address' };
  return { ok: true };
}

// ── Pools ────────────────────────────────────────────────────────────────────

export function listPoolsWithEntries(): RelayPoolWithEntries[] {
  const db = getDb();
  const pools = db.prepare('SELECT * FROM relay_pools ORDER BY is_default DESC, id').all() as RelayPool[];
  const entries = db.prepare('SELECT * FROM relay_pool_entries ORDER BY pool_id, id').all() as RelayPoolEntry[];
  const byPool = new Map<number, RelayPoolEntry[]>();
  for (const e of entries) {
    const list = byPool.get(e.pool_id) ?? [];
    list.push(e);
    byPool.set(e.pool_id, list);
  }
  return pools.map(p => ({
    ...p,
    entries: (byPool.get(p.id) ?? []).map(e => entryView(e, decryptAuthForView(e))),
  }));
}

export interface PoolInput {
  name: string;
  description?: string;
  is_default?: boolean;
  enabled?: boolean;
  mode?: RelayPoolMode;
  fallback?: RelayPoolFallback;
}

function clearOtherDefaults(db: ReturnType<typeof getDb>, exceptId?: number): void {
  if (exceptId != null) {
    db.prepare('UPDATE relay_pools SET is_default = 0, updated_at = datetime(\'now\') WHERE is_default = 1 AND id != ?').run(exceptId);
  } else {
    db.prepare('UPDATE relay_pools SET is_default = 0, updated_at = datetime(\'now\') WHERE is_default = 1').run();
  }
}

export function createPool(input: PoolInput): RelayPool {
  const db = getDb();
  const isDefault = input.is_default ? 1 : 0;
  return db.transaction(() => {
    if (isDefault) clearOtherDefaults(db);
    const result = db.prepare(`
      INSERT INTO relay_pools (name, description, is_default, enabled, mode, fallback)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      input.name,
      input.description ?? '',
      isDefault,
      input.enabled === false ? 0 : 1,
      input.mode ?? 'round-robin',
      input.fallback ?? 'direct',
    );
    return db.prepare('SELECT * FROM relay_pools WHERE id = ?').get(result.lastInsertRowid) as RelayPool;
  })();
}

export function updatePool(id: number, input: Partial<PoolInput>): RelayPool | undefined {
  const db = getDb();
  const existing = db.prepare('SELECT * FROM relay_pools WHERE id = ?').get(id) as RelayPool | undefined;
  if (!existing) return undefined;
  return db.transaction(() => {
    const sets: string[] = [];
    const values: (string | number | null)[] = [];
    if (input.name !== undefined) { sets.push('name = ?'); values.push(input.name); }
    if (input.description !== undefined) { sets.push('description = ?'); values.push(input.description); }
    if (input.mode !== undefined) { sets.push('mode = ?'); values.push(input.mode); }
    if (input.fallback !== undefined) { sets.push('fallback = ?'); values.push(input.fallback); }
    if (input.enabled !== undefined) { sets.push('enabled = ?'); values.push(input.enabled ? 1 : 0); }
    if (input.is_default !== undefined) {
      sets.push('is_default = ?');
      values.push(input.is_default ? 1 : 0);
      if (input.is_default) clearOtherDefaults(db, id);
    }
    sets.push("updated_at = datetime('now')");
    values.push(id);
    db.prepare(`UPDATE relay_pools SET ${sets.join(', ')} WHERE id = ?`).run(...values);
    return db.prepare('SELECT * FROM relay_pools WHERE id = ?').get(id) as RelayPool;
  })();
}

export function deletePool(id: number): boolean {
  const db = getDb();
  const result = db.prepare('DELETE FROM relay_pools WHERE id = ?').run(id);
  return result.changes > 0;
}

export function getDefaultPool(): RelayPool | undefined {
  return getDb().prepare(
    'SELECT * FROM relay_pools WHERE is_default = 1 AND enabled = 1 LIMIT 1',
  ).get() as RelayPool | undefined;
}

// ── Entries ──────────────────────────────────────────────────────────────────

export interface EntryInput {
  url: string;
  label?: string;
  /** Plaintext shared secret; '' / undefined = no auth. */
  auth?: string;
  enabled?: boolean;
}

function encryptAuth(auth: string | undefined): { encrypted: string | null; iv: string | null; authTag: string | null } {
  const secret = auth?.trim() ?? '';
  if (!secret) return { encrypted: null, iv: null, authTag: null };
  const { encrypted, iv, authTag } = encrypt(secret);
  return { encrypted, iv, authTag };
}

export function addEntry(poolId: number, input: EntryInput): RelayPoolEntry {
  const db = getDb();
  const auth = encryptAuth(input.auth);
  const result = db.prepare(`
    INSERT INTO relay_pool_entries (pool_id, url, label, auth_encrypted, auth_iv, auth_auth_tag, enabled)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    poolId,
    input.url.trim(),
    input.label ?? '',
    auth.encrypted,
    auth.iv,
    auth.authTag,
    input.enabled === false ? 0 : 1,
  );
  return db.prepare('SELECT * FROM relay_pool_entries WHERE id = ?').get(result.lastInsertRowid) as RelayPoolEntry;
}

export function updateEntry(poolId: number, entryId: number, input: Partial<EntryInput>): RelayPoolEntry | undefined {
  const db = getDb();
  const existing = db.prepare('SELECT * FROM relay_pool_entries WHERE id = ? AND pool_id = ?').get(entryId, poolId) as RelayPoolEntry | undefined;
  if (!existing) return undefined;
  const sets: string[] = [];
  const values: (string | number | null)[] = [];
  if (input.url !== undefined) { sets.push('url = ?'); values.push(input.url.trim()); }
  if (input.label !== undefined) { sets.push('label = ?'); values.push(input.label); }
  if (input.enabled !== undefined) { sets.push('enabled = ?'); values.push(input.enabled ? 1 : 0); }
  if (input.auth !== undefined) {
    const auth = encryptAuth(input.auth);
    sets.push('auth_encrypted = ?', 'auth_iv = ?', 'auth_auth_tag = ?');
    values.push(auth.encrypted, auth.iv, auth.authTag);
  }
  sets.push("updated_at = datetime('now')");
  values.push(entryId, poolId);
  db.prepare(`UPDATE relay_pool_entries SET ${sets.join(', ')} WHERE id = ? AND pool_id = ?`).run(...values);
  return db.prepare('SELECT * FROM relay_pool_entries WHERE id = ?').get(entryId) as RelayPoolEntry;
}

export function deleteEntry(poolId: number, entryId: number): boolean {
  const db = getDb();
  const result = db.prepare('DELETE FROM relay_pool_entries WHERE id = ? AND pool_id = ?').run(entryId, poolId);
  return result.changes > 0;
}

export function getEntry(poolId: number, entryId: number): RelayPoolEntry | undefined {
  return getDb().prepare('SELECT * FROM relay_pool_entries WHERE id = ? AND pool_id = ?').get(entryId, poolId) as RelayPoolEntry | undefined;
}

/** Probe one entry through the relay wire path (GET on the relay root with
 *  the entry's auth). Reports reachability + status + latency. */
export async function probeEntry(poolId: number, entryId: number): Promise<{ ok: boolean; status: number | null; latencyMs: number; error?: string } | null> {
  const entry = getEntry(poolId, entryId);
  if (!entry) return null;
  return testRelayEntry(entry);
}
