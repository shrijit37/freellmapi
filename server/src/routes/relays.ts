// REST API for egress relay pools — /api/relays (mounted with requireAuth in
// app.ts). Thin zod+auth wrapper over lib/relays.ts; auth secrets are write-
// only and masked on read (has_auth + last-4 hint).

import { Router } from 'express';
import type { Request, Response } from 'express';
import { z } from 'zod';
import {
  listPoolsWithEntries,
  createPool,
  updatePool,
  deletePool,
  addEntry,
  updateEntry,
  deleteEntry,
  getEntry,
  probeEntry,
  validateRelayEntryUrl,
} from '../lib/relays.js';

export const relaysRouter = Router();

const poolModeSchema = z.enum(['round-robin', 'sticky']);
const poolFallbackSchema = z.enum(['direct', 'fail']);

const createPoolSchema = z.object({
  name: z.string().trim().min(1).max(120),
  description: z.string().max(2000).optional(),
  is_default: z.boolean().optional(),
  enabled: z.boolean().optional(),
  mode: poolModeSchema.optional(),
  fallback: poolFallbackSchema.optional(),
});

const updatePoolSchema = z.object({
  name: z.string().trim().min(1).max(120).optional(),
  description: z.string().max(2000).optional(),
  is_default: z.boolean().optional(),
  enabled: z.boolean().optional(),
  mode: poolModeSchema.optional(),
  fallback: poolFallbackSchema.optional(),
}).refine(d => Object.keys(d).length > 0, { message: 'At least one field must be provided' });

const entryUrlSchema = z.string().trim().min(1).max(2048);
const entryAuthSchema = z.string().max(500).optional();

const createEntrySchema = z.object({
  url: entryUrlSchema,
  label: z.string().max(200).optional(),
  auth: entryAuthSchema,
  enabled: z.boolean().optional(),
});

const updateEntrySchema = z.object({
  url: entryUrlSchema.optional(),
  label: z.string().max(200).optional(),
  auth: entryAuthSchema,
  enabled: z.boolean().optional(),
}).refine(d => Object.keys(d).length > 0, { message: 'At least one field must be provided' });

function poolIdParam(req: Request): number | null {
  const id = Number(req.params.id);
  return Number.isInteger(id) && id > 0 ? id : null;
}

function entryIdParam(req: Request): number | null {
  const id = Number(req.params.entryId);
  return Number.isInteger(id) && id > 0 ? id : null;
}

function parseError(res: Response, err: unknown): void {
  res.status(400).json({ error: { message: err instanceof Error ? err.message : 'Invalid request' } });
}

// GET /api/relays — pools with entries (auth masked).
relaysRouter.get('/', (_req: Request, res: Response) => {
  res.json({ pools: listPoolsWithEntries() });
});

// POST /api/relays — create a pool.
relaysRouter.post('/', async (req: Request, res: Response) => {
  const parsed = createPoolSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: { message: parsed.error.errors.map(e => e.message).join(', ') } });
    return;
  }
  try {
    const pool = createPool(parsed.data);
    res.status(201).json({ pool });
  } catch (err) {
    parseError(res, err);
  }
});

// PUT /api/relays/:id — update pool fields (is_default clears others).
relaysRouter.put('/:id', async (req: Request, res: Response) => {
  const id = poolIdParam(req);
  if (id == null) { res.status(400).json({ error: { message: 'Invalid pool ID' } }); return; }
  const parsed = updatePoolSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: { message: parsed.error.errors.map(e => e.message).join(', ') } });
    return;
  }
  const pool = updatePool(id, parsed.data);
  if (!pool) { res.status(404).json({ error: { message: 'Pool not found' } }); return; }
  res.json({ pool });
});

// DELETE /api/relays/:id — delete pool + entries (FK cascade).
relaysRouter.delete('/:id', (req: Request, res: Response) => {
  const id = poolIdParam(req);
  if (id == null) { res.status(400).json({ error: { message: 'Invalid pool ID' } }); return; }
  if (!deletePool(id)) { res.status(404).json({ error: { message: 'Pool not found' } }); return; }
  res.json({ success: true });
});

// POST /api/relays/:id/entries — add an entry (URL validated + DNS-checked).
relaysRouter.post('/:id/entries', async (req: Request, res: Response) => {
  const id = poolIdParam(req);
  if (id == null) { res.status(400).json({ error: { message: 'Invalid pool ID' } }); return; }
  const parsed = createEntrySchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: { message: parsed.error.errors.map(e => e.message).join(', ') } });
    return;
  }
  const verdict = await validateRelayEntryUrl(parsed.data.url);
  if (!verdict.ok) {
    res.status(400).json({ error: { message: `Invalid relay URL: ${verdict.reason}` } });
    return;
  }
  try {
    const entry = addEntry(id, parsed.data);
    res.status(201).json({ entry });
  } catch (err) {
    parseError(res, err);
  }
});

// PUT /api/relays/:id/entries/:entryId — update an entry.
relaysRouter.put('/:id/entries/:entryId', async (req: Request, res: Response) => {
  const id = poolIdParam(req);
  const entryId = entryIdParam(req);
  if (id == null || entryId == null) { res.status(400).json({ error: { message: 'Invalid pool or entry ID' } }); return; }
  const parsed = updateEntrySchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: { message: parsed.error.errors.map(e => e.message).join(', ') } });
    return;
  }
  if (parsed.data.url !== undefined) {
    const verdict = await validateRelayEntryUrl(parsed.data.url);
    if (!verdict.ok) {
      res.status(400).json({ error: { message: `Invalid relay URL: ${verdict.reason}` } });
      return;
    }
  }
  const entry = updateEntry(id, entryId, parsed.data);
  if (!entry) { res.status(404).json({ error: { message: 'Entry not found' } }); return; }
  res.json({ entry });
});

// DELETE /api/relays/:id/entries/:entryId — remove an entry.
relaysRouter.delete('/:id/entries/:entryId', (req: Request, res: Response) => {
  const id = poolIdParam(req);
  const entryId = entryIdParam(req);
  if (id == null || entryId == null) { res.status(400).json({ error: { message: 'Invalid pool or entry ID' } }); return; }
  if (!deleteEntry(id, entryId)) { res.status(404).json({ error: { message: 'Entry not found' } }); return; }
  res.json({ success: true });
});

// POST /api/relays/:id/entries/:entryId/test — probe the relay.
relaysRouter.post('/:id/entries/:entryId/test', async (req: Request, res: Response) => {
  const id = poolIdParam(req);
  const entryId = entryIdParam(req);
  if (id == null || entryId == null) { res.status(400).json({ error: { message: 'Invalid pool or entry ID' } }); return; }
  if (!getEntry(id, entryId)) { res.status(404).json({ error: { message: 'Entry not found' } }); return; }
  const result = await probeEntry(id, entryId);
  if (!result) { res.status(404).json({ error: { message: 'Entry not found' } }); return; }
  res.json(result);
});
