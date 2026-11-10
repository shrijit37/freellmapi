// Migration: relay pools + per-key egress + OAuth key columns
// Created: 2026-11-10
//
// DOWN: reversible (DROP TABLE / DROP COLUMN, all guarded)
//
// Three related additions:
//
// 1. relay_pools / relay_pool_entries — named pools of HTTPS relay endpoints
//    (Cloudflare Workers / Vercel / Deno edge functions) that forward requests
//    to provider APIs from their own egress IPs. Protocol-compatible with
//    pi-freeflow's relay workers: x-relay-target, x-relay-path, x-relay-auth,
//    Host headers. Entries carry a shared secret (encrypted with the app
//    ENCRYPTION_KEY, same as api_keys.proxy_encrypted) and health columns for
//    cooldown/EWMA tracking.
//
// 2. api_keys.relay_mode / api_keys.relay_pool_id — per-key egress routing:
//    'inherit' (use the default pool, else global proxy), 'pool' (force this
//    key's assigned pool), 'direct' (bypass pools entirely). relay_pool_id is
//    the assignment; NULL means "the pool flagged is_default" for 'pool' mode.
//
// 3. api_keys.oauth_* columns — OAuth2 credential material for providers like
//    Antigravity that issue access+refresh tokens instead of static API keys.
//    encrypted_key still holds the credential, but as an AES-GCM blob whose
//    plaintext is a JSON document (see lib/oauth-credentials.ts); the columns
//    below carry only NON-secret bookkeeping so the health checker and router
//    can see expiry/refresh state without decrypting:
//      oauth_provider  — registry slug ('antigravity'), NULL for static keys
//      oauth_expires_at — epoch ms when the access token inside expires
//      oauth_email     — account label shown in the dashboard (not secret)
//    The refresh token itself lives INSIDE the encrypted_key JSON blob, never
//    in a plaintext column.
//
// Guarded like every other migration: catalog-sync re-runs migrations over a
// live schema, so CREATE/ALTER must be idempotent.

import type { Db } from '../types.js';

function hasTable(db: Db, name: string): boolean {
  return Boolean(
    db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?").get(name),
  );
}

function hasColumn(db: Db, table: string, column: string): boolean {
  const columns = db.prepare(`PRAGMA table_info(${table})`).all() as { name: string }[];
  return columns.some(col => col.name === column);
}

export function up(db: Db): void {
  if (!hasTable(db, 'relay_pools')) {
    db.prepare(`
      CREATE TABLE relay_pools (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        is_default INTEGER NOT NULL DEFAULT 0,
        enabled INTEGER NOT NULL DEFAULT 1,
        mode TEXT NOT NULL DEFAULT 'round-robin',
        fallback TEXT NOT NULL DEFAULT 'direct',
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      )
    `).run();
  }

  if (!hasTable(db, 'relay_pool_entries')) {
    db.prepare(`
      CREATE TABLE relay_pool_entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pool_id INTEGER NOT NULL REFERENCES relay_pools(id) ON DELETE CASCADE,
        url TEXT NOT NULL,
        label TEXT NOT NULL DEFAULT '',
        auth_encrypted TEXT,
        auth_iv TEXT,
        auth_auth_tag TEXT,
        enabled INTEGER NOT NULL DEFAULT 1,
        cooldown_until TEXT,
        last_status INTEGER,
        last_error TEXT,
        consecutive_failures INTEGER NOT NULL DEFAULT 0,
        ewma_latency_ms REAL,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now')),
        UNIQUE(pool_id, url)
      )
    `).run();
    db.prepare('CREATE INDEX idx_relay_pool_entries_pool ON relay_pool_entries(pool_id)').run();
  }

  for (const col of [
    ["relay_mode", "TEXT NOT NULL DEFAULT 'inherit'"],
    ['relay_pool_id', 'INTEGER'],
    ['oauth_provider', 'TEXT'],
    ['oauth_expires_at', 'INTEGER'],
    ['oauth_email', 'TEXT'],
  ] as const) {
    if (!hasColumn(db, 'api_keys', col[0])) {
      db.prepare(`ALTER TABLE api_keys ADD COLUMN ${col[0]} ${col[1]}`).run();
    }
  }
}

export function down(db: Db): void {
  if (hasTable(db, 'relay_pool_entries')) {
    db.prepare('DROP TABLE relay_pool_entries').run();
  }
  if (hasTable(db, 'relay_pools')) {
    db.prepare('DROP TABLE relay_pools').run();
  }
  for (const col of ['relay_mode', 'relay_pool_id', 'oauth_provider', 'oauth_expires_at', 'oauth_email']) {
    if (hasColumn(db, 'api_keys', col)) {
      db.prepare(`ALTER TABLE api_keys DROP COLUMN ${col}`).run();
    }
  }
}
