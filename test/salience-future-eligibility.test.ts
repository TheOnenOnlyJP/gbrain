/**
 * Recent-salience future eligibility (PGLite, unit lane).
 *
 * Calendar-day and plan pages carry future effective dates. Before this
 * guard they entered every recent-salience window with zero signal, and the
 * recency term (h / (h + days_old)) grew as days_old went negative, so a page
 * dated ~90 days ahead outranked every real page. Now:
 *   - a future-dated page with no emotional weight and no active take is
 *     omitted by default;
 *   - a future-dated page with a signal stays eligible;
 *   - `includeFuture` (MCP `include_future`) admits them explicitly;
 *   - holder-restricted reads judge "signal" by permitted holders' takes only,
 *     never by stored emotional_weight (matching the restricted score);
 *   - recency age clamps at zero, so a future date scores like today.
 * Postgres parity: test/e2e/engine-parity-salience.test.ts.
 */
import { describe, test, expect, beforeAll, afterAll } from 'bun:test';
import { PGLiteEngine } from '../src/core/pglite-engine.ts';
import { operations, type OperationContext } from '../src/core/operations.ts';
import type { SalienceOpts, SalienceResult } from '../src/core/types.ts';
import { DEFAULT_FALLBACK } from '../src/core/search/recency-decay.ts';

let engine: PGLiteEngine;
const get_recent_salience = operations.find(o => o.name === 'get_recent_salience')!;

const PAST = ['eligibility/past-zero', 'eligibility/today-zero', 'eligibility/undated-zero'];
const FUTURE_WITH_SIGNAL = [
  'eligibility/future-emotional',
  'eligibility/future-take-reader',
  'eligibility/future-take-owner',
];
const FUTURE_WITHOUT_SIGNAL = ['eligibility/future-zero', 'eligibility/future-inactive-take'];
const ALL_LIVE = [...PAST, ...FUTURE_WITH_SIGNAL, ...FUTURE_WITHOUT_SIGNAL];

async function pageId(slug: string): Promise<number> {
  const rows = await engine.executeRaw<{ id: number }>('SELECT id FROM pages WHERE slug = $1', [slug]);
  return Number(rows[0].id);
}

async function recent(opts: Partial<SalienceOpts> = {}): Promise<SalienceResult[]> {
  return engine.getRecentSalience({ days: 7, limit: 50, slugPrefix: 'eligibility/', ...opts });
}

const slugsOf = (rows: SalienceResult[]) => rows.map(r => r.slug).sort();
const sorted = (slugs: string[]) => [...slugs].sort();

beforeAll(async () => {
  engine = new PGLiteEngine();
  await engine.connect({});
  await engine.initSchema();

  for (const slug of [...ALL_LIVE, 'eligibility/future-deleted']) {
    await engine.putPage(slug, { type: 'note', title: slug, compiled_truth: 'salience eligibility fixture' });
  }
  await engine.executeRaw(
    `UPDATE pages
        SET effective_date = CASE slug
          WHEN 'eligibility/past-zero' THEN now() - interval '1 day'
          WHEN 'eligibility/today-zero' THEN now()
          WHEN 'eligibility/undated-zero' THEN NULL
          ELSE now() + interval '30 days'
        END
      WHERE slug LIKE 'eligibility/%'`,
  );
  await engine.executeRaw(
    `UPDATE pages SET emotional_weight = 0.25 WHERE slug IN ('eligibility/future-emotional', 'eligibility/future-deleted')`,
  );
  await engine.addTakesBatch([
    { page_id: await pageId('eligibility/future-take-reader'), row_num: 0, claim: 'reader signal', kind: 'take', holder: 'reader', weight: 0.5 },
    { page_id: await pageId('eligibility/future-take-owner'), row_num: 0, claim: 'owner signal', kind: 'take', holder: 'owner', weight: 0.5 },
    { page_id: await pageId('eligibility/future-inactive-take'), row_num: 0, claim: 'retired signal', kind: 'take', holder: 'reader', weight: 0.5, active: false },
    { page_id: await pageId('eligibility/future-deleted'), row_num: 0, claim: 'deleted signal', kind: 'take', holder: 'reader', weight: 0.5 },
  ]);
  await engine.softDeletePage('eligibility/future-deleted');
}, 60_000);

afterAll(async () => {
  if (engine) await engine.disconnect();
}, 60_000);

describe('getRecentSalience future eligibility (unrestricted)', () => {
  for (const recency_bias of ['flat', 'on'] as const) {
    test(`recency_bias=${recency_bias}: future zero-signal pages are excluded by default`, async () => {
      const rows = await recent({ recency_bias });
      expect(slugsOf(rows)).toEqual(sorted([...PAST, ...FUTURE_WITH_SIGNAL]));
    });

    test(`recency_bias=${recency_bias}: includeFuture admits them, never soft-deleted pages`, async () => {
      const rows = await recent({ recency_bias, includeFuture: true });
      expect(slugsOf(rows)).toEqual(sorted(ALL_LIVE));
    });
  }

  test('inactive takes are not a signal', async () => {
    const rows = await recent();
    expect(rows.some(r => r.slug === 'eligibility/future-inactive-take')).toBe(false);
  });

  test('past, today and undated pages are unaffected by includeFuture', async () => {
    for (const recency_bias of ['flat', 'on'] as const) {
      const pick = (rows: SalienceResult[]) =>
        rows.filter(r => PAST.includes(r.slug)).map(r => [r.slug, r.take_count, r.emotional_weight]).sort();
      const without = await recent({ recency_bias });
      const withFuture = await recent({ recency_bias, includeFuture: true });
      expect(pick(without)).toHaveLength(PAST.length);
      expect(pick(withFuture)).toEqual(pick(without));
    }
  });

  test('a future date earns no recency bonus beyond today (age clamps at zero)', async () => {
    const rows = await recent({ recency_bias: 'on', includeFuture: true });
    const byslug = new Map(rows.map(r => [r.slug, r]));
    const future = byslug.get('eligibility/future-zero')!;
    const today = byslug.get('eligibility/today-zero')!;
    expect(Number.isFinite(future.score)).toBe(true);
    // Unclamped, 30 days ahead on the 90-day fallback scored 0.3 * 90 / 60 = 0.45.
    expect(future.score).toBeCloseTo(DEFAULT_FALLBACK.coefficient, 6);
    expect(future.score).toBeCloseTo(today.score, 3);
    expect(rows.every(r => Number.isFinite(r.score))).toBe(true);
  });
});

describe('getRecentSalience future eligibility (holder-restricted)', () => {
  test('signal = permitted holders\' active takes; stored emotional weight is ignored', async () => {
    const rows = await recent({ recency_bias: 'on', takesHoldersAllowList: ['reader'] });
    expect(slugsOf(rows)).toEqual(sorted([...PAST, 'eligibility/future-take-reader']));
    expect(rows.every(r => r.emotional_weight === 0)).toBe(true);
  });

  test('an empty allow-list leaves no future page with a signal', async () => {
    const rows = await recent({ takesHoldersAllowList: [] });
    expect(slugsOf(rows)).toEqual(sorted(PAST));
  });

  test('includeFuture still admits every live future page under restriction', async () => {
    const rows = await recent({ takesHoldersAllowList: ['reader'], includeFuture: true });
    expect(slugsOf(rows)).toEqual(sorted(ALL_LIVE));
  });
});

describe('get_recent_salience include_future param', () => {
  const localCtx = () => ({
    engine: engine as any,
    config: {} as any,
    logger: console as any,
    dryRun: false,
    remote: false,
  }) as OperationContext;

  test('publishes include_future as a boolean param', () => {
    expect(get_recent_salience.params.include_future).toMatchObject({ type: 'boolean' });
  });

  test('defaults to excluding future zero-signal pages and opts in on true only', async () => {
    const call = async (p: Record<string, unknown>) =>
      slugsOf(await get_recent_salience.handler(localCtx(), { days: 7, slugPrefix: 'eligibility/', ...p }) as SalienceResult[]);
    const hidden = await call({});
    expect(hidden).not.toContain('eligibility/future-zero');
    expect(await call({ include_future: 'true' })).toEqual(hidden);
    expect(await call({ include_future: true })).toContain('eligibility/future-zero');
  });
});
