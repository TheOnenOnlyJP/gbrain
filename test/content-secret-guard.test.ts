import { describe, expect, test } from 'bun:test';
import {
  ContentSecretGuardError,
  sanitizeContentForImport,
  sanitizeContentFieldsForImport,
  sanitizeStructuredContentForImport,
} from '../src/core/content-secret-guard.ts';

const FIELD_BOUNDARY_FIXTURE = '\0GBRAIN_CONTENT_FIELD_BOUNDARY\0';

describe('content secret guard', () => {
  test('redacts provider keys with the in-process baseline before persistence', async () => {
    const secret = `pa-${'A1b2'.repeat(6)}`;
    const result = await sanitizeContentForImport(`Voyage key: ${secret}`, 'notes/example.md', {
      command: '',
      required: false,
    });

    expect(result.changed).toBe(true);
    expect(result.nativeRedactions).toBe(1);
    expect(result.externalApplied).toBe(false);
    expect(result.content).toContain('<REDACTED:voyage>');
    expect(result.content).not.toContain(secret);
  });

  test('passes the baseline-redacted payload through the configured external sanitizer', async () => {
    const seen: string[] = [];
    const result = await sanitizeContentForImport('A custom-marker appears here.', 'notes/example.md', {
      command: '/synthetic/sanitizer',
      required: true,
      runExternal: async (command, content, displayPath) => {
        seen.push(command, content, displayPath);
        return content.replace('custom-marker', '<REDACTED:custom>');
      },
    });

    expect(seen).toEqual([
      '/synthetic/sanitizer',
      'A custom-marker appears here.',
      'notes/example.md',
    ]);
    expect(result.externalApplied).toBe(true);
    expect(result.changed).toBe(true);
    expect(result.content).toBe('A <REDACTED:custom> appears here.');
  });

  test('fails closed when an external sanitizer is required but absent', async () => {
    await expect(
      sanitizeContentForImport('clean', 'notes/example.md', { command: '', required: true }),
    ).rejects.toBeInstanceOf(ContentSecretGuardError);
  });

  test('does not expose an external runner error message', async () => {
    const sensitiveError = 'scanner leaked a matched value';
    try {
      await sanitizeContentForImport('clean', 'notes/example.md', {
        command: '/synthetic/sanitizer',
        runExternal: async () => {
          throw new Error(sensitiveError);
        },
      });
      throw new Error('expected the sanitizer to fail');
    } catch (error: unknown) {
      expect(error).toBeInstanceOf(ContentSecretGuardError);
      expect(error instanceof Error ? error.message : String(error)).not.toContain(sensitiveError);
    }
  });

  test('leaves clean prose unchanged when no external sanitizer is configured', async () => {
    const content = 'Ordinary prose without credentials.';
    const result = await sanitizeContentForImport(content, 'notes/example.md', {
      command: '',
      required: false,
    });
    expect(result).toEqual({
      content,
      changed: false,
      nativeRedactions: 0,
      externalApplied: false,
    });
  });
});

describe('sanitizeContentFieldsForImport', () => {
  test('sanitizes multiple fields with one external invocation and preserves boundaries', async () => {
    let calls = 0;
    const result = await sanitizeContentFieldsForImport(
      ['fact with token abcdefghijklmnopqrstuvwxyz', 'conversation provenance', 'people/example'],
      'memory-verb/remember',
      {
        command: '/guard',
        runExternal: async (_command, content) => {
          calls += 1;
          return content.replace('abcdefghijklmnopqrstuvwxyz', '<REDACTED:test-token>');
        },
      },
    );

    expect(calls).toBe(1);
    expect(result).toEqual([
      'fact with token <REDACTED:test-token>',
      'conversation provenance',
      'people/example',
    ]);
  });

  test('retries fields independently when a finding consumes the field boundary', async () => {
    let calls = 0;
    const result = await sanitizeContentFieldsForImport(['one', 'two'], 'memory-verb/remember', {
      command: '/guard',
      runExternal: async (_command, content) => {
        calls += 1;
        return content.includes('GBRAIN_CONTENT_FIELD_BOUNDARY')
          ? content.replace(FIELD_BOUNDARY_FIXTURE, '<REDACTED:overlap>')
          : content;
      },
    });

    expect(result).toEqual(['one', 'two']);
    expect(calls).toBe(3);
  });
});

describe('sanitizeStructuredContentForImport', () => {
  test('redacts nested JSON-compatible values without changing their shape', async () => {
    const raw = `pa-${'A1b2'.repeat(6)}`;
    const result = await sanitizeStructuredContentForImport(
      { source: 'crm', data: { authorization: `Bearer ${raw}`, nested: [1, true] } },
      'raw-data/people/example',
      { command: '', required: false },
    );

    expect(result.source).toBe('crm');
    expect(result.data.nested).toEqual([1, true]);
    expect(result.data.authorization).not.toContain(raw);
    expect(result.data.authorization).toContain('<REDACTED:');
  });

  test('fails closed if an external sanitizer damages JSON', async () => {
    await expect(
      sanitizeStructuredContentForImport({ token: 'clean' }, 'raw-data/test', {
        command: '/guard',
        runExternal: async () => 'not-json',
      }),
    ).rejects.toThrow(ContentSecretGuardError);
  });
});
