// Relay pool unit tests: selection order, cooldown skip, failover, fallback
// policy, sticky pinning, wire-protocol headers, SSRF rejection, auth header.
// All fetch calls are mocked — no real network.

import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest';
import { initDb, getDb } from '../../db/index.js';
import {
  validateRelayUrl,
  validateRelayTarget,
  buildRelayRequest,
  relayFetch,
  resolvePoolForKey,
  RelayExhaustedError,
  type RelayPool,
} from '../../lib/relay-pool.js';
import { proxyFetch, withRequestEgress, applyProxyUrl, applyProxyEnabled, applyProxyBypass } from '../../lib/proxy.js';
import { createPool, addEntry } from '../../lib/relays.js';

beforeAll(() => {
  process.env.ENCRYPTION_KEY = '0'.repeat(64);
  initDb(':memory:');
});

const TARGET = 'https://api.provider.test/v1/chat/completions?x=1';

function makePool(mode: 'round-robin' | 'sticky' = 'round-robin', fallback: 'direct' | 'fail' = 'direct', isDefault = true): RelayPool {
  return createPool({ name: `pool-${Math.random()}`, mode, fallback, is_default: isDefault });
}

function addRelay(poolId: number, url: string, auth?: string): number {
  const entry = addEntry(poolId, { url, auth });
  return entry.id;
}

function mockFetchSequence(handlers: Array<(url: string, init?: RequestInit) => Response | Promise<Response> | Error>) {
  let i = 0;
  return vi.spyOn(global, 'fetch').mockImplementation(async (input: any, init?: any) => {
    const handler = handlers[Math.min(i++, handlers.length - 1)];
    const out = handler(String(input), init);
    if (out instanceof Error) throw out;
    return out;
  });
}

function okResponse(status = 200): Response {
  return new Response('{"ok":true}', { status });
}

describe('validateRelayUrl', () => {
  it('accepts a public https URL', () => {
    expect(validateRelayUrl('https://relay.example.com').ok).toBe(true);
    expect(validateRelayUrl('https://relay.example.com:8443/base').ok).toBe(true);
  });

  it('rejects non-https, credentials, loopback and private hosts', () => {
    expect(validateRelayUrl('http://relay.example.com').ok).toBe(false);
    expect(validateRelayUrl('https://user:pass@relay.example.com').ok).toBe(false);
    expect(validateRelayUrl('https://127.0.0.1').ok).toBe(false);
    expect(validateRelayUrl('https://localhost').ok).toBe(false);
    expect(validateRelayUrl('https://10.0.0.1').ok).toBe(false);
    expect(validateRelayUrl('https://192.168.1.1').ok).toBe(false);
    expect(validateRelayUrl('https://169.254.169.254').ok).toBe(false);
    expect(validateRelayUrl('https://[::1]').ok).toBe(false);
    expect(validateRelayUrl('not a url').ok).toBe(false);
  });
});

describe('validateRelayTarget', () => {
  it('accepts public https/http targets', () => {
    expect(validateRelayTarget('https://api.openai.com/v1').ok).toBe(true);
  });
  it('rejects private/metadata targets', () => {
    expect(validateRelayTarget('https://169.254.169.254/latest').ok).toBe(false);
    expect(validateRelayTarget('http://localhost:11434').ok).toBe(false);
    expect(validateRelayTarget('https://10.1.2.3').ok).toBe(false);
  });
});

describe('buildRelayRequest', () => {
  it('sets x-relay-target/path/auth and Host headers', () => {
    const { url, init } = buildRelayRequest(new URL('https://relay-a.example.com'), TARGET, {
      method: 'POST',
      headers: { Authorization: 'Bearer k', 'Content-Type': 'application/json' },
      body: '{}',
    }, 's3cret');
    const headers = new Headers(init.headers);
    expect(url).toBe('https://relay-a.example.com/v1/chat/completions?x=1');
    expect(headers.get('x-relay-target')).toBe(TARGET);
    expect(headers.get('x-relay-path')).toBe('/v1/chat/completions?x=1');
    expect(headers.get('x-relay-auth')).toBe('s3cret');
    expect(headers.get('host')).toBe('api.provider.test');
    expect(headers.get('authorization')).toBe('Bearer k');
    expect(init.redirect).toBe('manual');
  });

  it('omits x-relay-auth when no secret is set', () => {
    const { init } = buildRelayRequest(new URL('https://relay-a.example.com'), TARGET, {}, '');
    const headers = new Headers(init.headers);
    expect(headers.get('x-relay-auth')).toBeNull();
    expect(headers.get('x-relay-target')).toBe(TARGET);
  });
});

describe('resolvePoolForKey', () => {
  beforeEach(() => {
    getDb().prepare('DELETE FROM relay_pool_entries').run();
    getDb().prepare('DELETE FROM relay_pools').run();
  });

  it('direct mode resolves no pool', () => {
    makePool('round-robin', 'direct', true);
    expect(resolvePoolForKey('direct', null)).toBeUndefined();
  });
  it('inherit uses the default pool', () => {
    const pool = makePool('round-robin', 'direct', true);
    expect(resolvePoolForKey('inherit', null)?.id).toBe(pool.id);
    expect(resolvePoolForKey(undefined, null)?.id).toBe(pool.id);
  });
  it('pool mode uses assigned pool, falling back to default when id null', () => {
    const def = makePool('round-robin', 'direct', true);
    const other = makePool('sticky', 'fail', false);
    expect(resolvePoolForKey('pool', other.id)?.id).toBe(other.id);
    expect(resolvePoolForKey('pool', null)?.id).toBe(def.id);
  });
});

describe('relayFetch', () => {
  beforeEach(() => {
    getDb().prepare('DELETE FROM relay_pool_entries').run();
    getDb().prepare('DELETE FROM relay_pools').run();
  });
  afterEach(() => vi.restoreAllMocks());

  it('round-robin rotates across healthy entries', async () => {
    const pool = makePool('round-robin');
    addRelay(pool.id, 'https://relay-a.example.com');
    addRelay(pool.id, 'https://relay-b.example.com');
    const seen: string[] = [];
    mockFetchSequence([
      (u) => { seen.push(u); return okResponse(); },
      (u) => { seen.push(u); return okResponse(); },
      (u) => { seen.push(u); return okResponse(); },
    ]);
    await relayFetch(pool, TARGET, { method: 'POST' });
    await relayFetch(pool, TARGET, { method: 'POST' });
    await relayFetch(pool, TARGET, { method: 'POST' });
    expect(seen[0]).toContain('relay-a');
    expect(seen[1]).toContain('relay-b');
    expect(seen[2]).toContain('relay-a');
  });

  it('skips entries in cooldown and disabled entries', async () => {
    const pool = makePool('round-robin');
    const a = addRelay(pool.id, 'https://relay-a.example.com');
    addRelay(pool.id, 'https://relay-b.example.com');
    // Cool entry A down via update.
    getDb().prepare("UPDATE relay_pool_entries SET cooldown_until = datetime('now', '+1 hour') WHERE id = ?").run(a);
    const seen: string[] = [];
    mockFetchSequence([(u) => { seen.push(u); return okResponse(); }]);
    const res = await relayFetch(pool, TARGET, {});
    expect(res.ok).toBe(true);
    expect(seen[0]).toContain('relay-b');
  });

  it('fails over on 429 then succeeds on next entry', async () => {
    const pool = makePool('round-robin');
    addRelay(pool.id, 'https://relay-a.example.com');
    addRelay(pool.id, 'https://relay-b.example.com');
    const seen: string[] = [];
    mockFetchSequence([
      (u) => { seen.push(u); return new Response('rate limited', { status: 429 }); },
      (u) => { seen.push(u); return okResponse(); },
    ]);
    const res = await relayFetch(pool, TARGET, {});
    expect(res.ok).toBe(true);
    expect(seen).toHaveLength(2);
    expect(seen[0]).toContain('relay-a');
    expect(seen[1]).toContain('relay-b');
    // Entry A should now be cooling.
    const row = getDb().prepare('SELECT consecutive_failures, cooldown_until FROM relay_pool_entries ORDER BY id LIMIT 1').get() as any;
    expect(row.consecutive_failures).toBe(1);
    expect(row.cooldown_until).toBeTruthy();
  });

  it('fails over on transport error / timeout', async () => {
    const pool = makePool('round-robin');
    addRelay(pool.id, 'https://relay-a.example.com');
    addRelay(pool.id, 'https://relay-b.example.com');
    const seen: string[] = [];
    mockFetchSequence([
      (u) => { seen.push(u); throw new Error('fetch failed'); },
      (u) => { seen.push(u); return okResponse(); },
    ]);
    const res = await relayFetch(pool, TARGET, {});
    expect(res.ok).toBe(true);
    expect(seen).toHaveLength(2);
  });

  it('returns exhausted when all entries fail', async () => {
    const pool = makePool('round-robin');
    addRelay(pool.id, 'https://relay-a.example.com');
    addRelay(pool.id, 'https://relay-b.example.com');
    mockFetchSequence([
      () => new Response('x', { status: 503 }),
      () => new Response('x', { status: 503 }),
      () => new Response('x', { status: 503 }),
    ]);
    const res = await relayFetch(pool, TARGET, {});
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe('exhausted');
  });

  it('sticky mode pins one entry per scope until it fails', async () => {
    const pool = makePool('sticky');
    addRelay(pool.id, 'https://relay-a.example.com');
    addRelay(pool.id, 'https://relay-b.example.com');
    const seen: string[] = [];
    mockFetchSequence([
      (u) => { seen.push(u); return okResponse(); },
      (u) => { seen.push(u); return okResponse(); },
      // Third request: the pinned entry fails once, rolls to the second.
      (u) => { seen.push(u); return new Response('x', { status: 500 }); },
      (u) => { seen.push(u); return okResponse(); },
      (u) => { seen.push(u); return okResponse(); },
    ]);
    await relayFetch(pool, TARGET, {}, { stickyScope: 'key-1' });
    await relayFetch(pool, TARGET, {}, { stickyScope: 'key-1' });
    // Same scope → same pinned entry (relay-a both times).
    expect(seen[0]).toContain('relay-a');
    expect(seen[1]).toContain('relay-a');
    // key-1's pinned entry (relay-a) is tried first and fails; the same
    // request then rolls over to relay-b and succeeds.
    const res = await relayFetch(pool, TARGET, {}, { stickyScope: 'key-1' });
    expect(res.ok).toBe(true);
    expect(seen[2]).toContain('relay-a'); // pinned entry attempted
    expect(seen[3]).toContain('relay-b'); // failover within the request
    // Next key-1 request re-pins: relay-a is cooling, so it picks relay-b.
    await relayFetch(pool, TARGET, {}, { stickyScope: 'key-1' });
    expect(seen[4]).toContain('relay-b');
  });

  it('forwards upstream 401 without cooling the relay (non-worker shape)', async () => {
    const pool = makePool('round-robin');
    addRelay(pool.id, 'https://relay-a.example.com');
    addRelay(pool.id, 'https://relay-b.example.com');
    // A large provider-specific 401 body is NOT the worker rejection shape.
    const upstream401 = new Response(JSON.stringify({ error: { message: 'Incorrect API key provided', type: 'invalid_request_error' } }), { status: 401 });
    const seen: string[] = [];
    mockFetchSequence([
      (u) => { seen.push(u); return upstream401; },
      (u) => { seen.push(u); return okResponse(); },
    ]);
    const res = await relayFetch(pool, TARGET, {});
    // 401 non-worker-shape → treated as upstream answer, returned as-is.
    expect(res.ok).toBe(true);
    if (res.ok) expect(res.response.status).toBe(401);
    expect(seen).toHaveLength(1);
    // No cooldown recorded.
    const row = getDb().prepare('SELECT consecutive_failures FROM relay_pool_entries ORDER BY id LIMIT 1').get() as any;
    expect(row.consecutive_failures).toBe(0);
  });

  it('cools the relay on worker-shaped 401 rejection', async () => {
    const pool = makePool('round-robin');
    addRelay(pool.id, 'https://relay-a.example.com');
    addRelay(pool.id, 'https://relay-b.example.com');
    const worker401 = new Response(JSON.stringify({ error: 'unauthorized' }), { status: 401 });
    const seen: string[] = [];
    mockFetchSequence([
      (u) => { seen.push(u); return worker401; },
      (u) => { seen.push(u); return okResponse(); },
    ]);
    const res = await relayFetch(pool, TARGET, {});
    expect(res.ok).toBe(true);
    expect(seen).toHaveLength(2);
    const row = getDb().prepare('SELECT consecutive_failures FROM relay_pool_entries ORDER BY id LIMIT 1').get() as any;
    expect(row.consecutive_failures).toBe(1);
  });

  it('sends x-relay-auth only when the entry has a secret', async () => {
    const pool = makePool('round-robin');
    addRelay(pool.id, 'https://relay-a.example.com', 'topsecret');
    let captured: RequestInit | undefined;
    mockFetchSequence([(u, init) => { captured = init; return okResponse(); }]);
    await relayFetch(pool, TARGET, { method: 'POST' });
    const headers = new Headers(captured?.headers);
    expect(headers.get('x-relay-auth')).toBe('topsecret');
    expect(headers.get('x-relay-target')).toBe(TARGET);
    expect(headers.get('host')).toBe('api.provider.test');
  });

  it('rejects private relay targets before any fetch', async () => {
    const pool = makePool('round-robin');
    addRelay(pool.id, 'https://relay-a.example.com');
    const spy = vi.spyOn(global, 'fetch');
    const res = await relayFetch(pool, 'http://169.254.169.254/latest', {});
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe('blocked-target');
    expect(spy).not.toHaveBeenCalled();
  });

  it('returns no-pool when pool is undefined', async () => {
    const res = await relayFetch(undefined, TARGET, {});
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe('no-pool');
  });
});

describe('fallback policy (via dispatchFetch contract)', () => {
  it('RelayExhaustedError is thrown for fallback=fail pools by the caller', () => {
    // relayFetch itself returns {ok:false}; the throw lives in proxy.ts
    // dispatchFetch. Verify the error class exists and is an Error.
    const err = new RelayExhaustedError('pool exhausted');
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe('RelayExhaustedError');
  });
});

describe('dispatchFetch egress integration', () => {
  beforeEach(() => {
    getDb().prepare('DELETE FROM relay_pool_entries').run();
    getDb().prepare('DELETE FROM relay_pools').run();
    for (const name of ['PROXY_URL', 'ALL_PROXY', 'HTTPS_PROXY', 'HTTP_PROXY', 'NO_PROXY']) {
      delete process.env[name];
      delete process.env[name.toLowerCase()];
    }
    applyProxyEnabled(true);
    applyProxyBypass('');
    applyProxyUrl('');
  });
  afterEach(() => vi.restoreAllMocks());

  it('fallback=fail throws RelayExhaustedError when all relays fail', async () => {
    const pool = makePool('round-robin', 'fail', true);
    addRelay(pool.id, 'https://relay-a.example.com');
    mockFetchSequence([() => new Response('x', { status: 503 })]);
    await expect(
      withRequestEgress({ relayMode: 'inherit' }, () => proxyFetch(TARGET, { method: 'POST' })),
    ).rejects.toBeInstanceOf(RelayExhaustedError);
  });

  it('fallback=direct falls through to a direct fetch when all relays fail', async () => {
    const pool = makePool('round-robin', 'direct', true);
    addRelay(pool.id, 'https://relay-a.example.com');
    const seen: string[] = [];
    mockFetchSequence([
      (u) => { seen.push(u); return new Response('x', { status: 503 }); }, // relay attempt
      (u) => { seen.push(u); return okResponse(); },                        // direct fallback
    ]);
    const res = await withRequestEgress({ relayMode: 'inherit' }, () => proxyFetch(TARGET, { method: 'POST' }));
    expect(res.status).toBe(200);
    expect(seen[0]).toContain('relay-a');
    expect(seen[1]).toBe(TARGET); // direct fetch to the upstream URL
  });

  it('relayMode=direct bypasses pools entirely', async () => {
    makePool('round-robin', 'fail', true);
    const seen: string[] = [];
    mockFetchSequence([(u) => { seen.push(u); return okResponse(); }]);
    const res = await withRequestEgress({ relayMode: 'direct' }, () => proxyFetch(TARGET, { method: 'POST' }));
    expect(res.status).toBe(200);
    expect(seen[0]).toBe(TARGET);
  });

  it('per-key proxyUrl takes precedence over relay pools', async () => {
    const pool = makePool('round-robin', 'fail', true);
    addRelay(pool.id, 'https://relay-a.example.com');
    // A dead SOCKS proxy proves precedence: dispatchFetch enters the per-key
    // branch BEFORE the relay-pool block, so the request dies on the proxy
    // connection and never reaches a relay worker or the direct path.
    const seen: string[] = [];
    mockFetchSequence([(u) => { seen.push(u); return okResponse(); }]);
    await expect(
      withRequestEgress({ proxyUrl: 'socks5://127.0.0.1:1', relayMode: 'inherit' }, () => proxyFetch(TARGET, { method: 'POST' })),
    ).rejects.toThrow();
    expect(seen.every(u => !u.includes('relay-a'))).toBe(true);
  });
});
