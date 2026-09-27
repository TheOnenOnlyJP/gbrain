/**
 * Credential redaction for content that is about to enter the brain.
 *
 * The in-process scanner is the fast baseline. Operators can configure a
 * broader external sanitizer with GBRAIN_CONTENT_SANITIZER; when
 * GBRAIN_CONTENT_SANITIZER_REQUIRED=1, absence or failure blocks the write.
 * The external process receives content on stdin and must return sanitized
 * content on stdout. Its stderr is never copied into an error because a
 * third-party scanner may include matched values there.
 */

import { redactFindings } from './secret-scan.ts';

const EXTERNAL_TIMEOUT_MS = 45_000;
const MAX_SANITIZED_BYTES = 6_000_000;
const FIELD_SEPARATOR = '\0GBRAIN_CONTENT_FIELD_BOUNDARY\0';

export class ContentSecretGuardError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ContentSecretGuardError';
  }
}

export interface ContentSecretGuardResult {
  content: string;
  changed: boolean;
  nativeRedactions: number;
  externalApplied: boolean;
}

export type ExternalSanitizerRunner = (
  command: string,
  content: string,
  displayPath: string,
) => Promise<string>;

export interface ContentSecretGuardOptions {
  command?: string;
  required?: boolean;
  runExternal?: ExternalSanitizerRunner;
}

/**
 * Sanitize several independently stored fields with one scanner invocation.
 * The NUL-delimited boundary cannot be stored in Postgres text values and is
 * deliberately low entropy so it is not itself a credential candidate.
 */
export async function sanitizeContentFieldsForImport(
  fields: readonly string[],
  displayPath: string,
  options: ContentSecretGuardOptions = {},
): Promise<readonly string[]> {
  if (fields.length === 0) return [];
  if (fields.length === 1) {
    return [(await sanitizeContentForImport(fields[0] ?? '', displayPath, options)).content];
  }
  if (fields.some((field) => field.includes(FIELD_SEPARATOR))) {
    const midpoint = Math.floor(fields.length / 2);
    return [
      ...(await sanitizeContentFieldsForImport(fields.slice(0, midpoint), displayPath, options)),
      ...(await sanitizeContentFieldsForImport(fields.slice(midpoint), displayPath, options)),
    ];
  }
  const guarded = await sanitizeContentForImport(fields.join(FIELD_SEPARATOR), displayPath, options);
  const sanitized = guarded.content.split(FIELD_SEPARATOR);
  if (sanitized.length !== fields.length) {
    const midpoint = Math.floor(fields.length / 2);
    return [
      ...(await sanitizeContentFieldsForImport(fields.slice(0, midpoint), displayPath, options)),
      ...(await sanitizeContentFieldsForImport(fields.slice(midpoint), displayPath, options)),
    ];
  }
  return sanitized;
}

/** Sanitize a JSON-compatible payload and fail closed if redaction damages its shape. */
export async function sanitizeStructuredContentForImport<T>(
  value: T,
  displayPath: string,
  options: ContentSecretGuardOptions = {},
): Promise<T> {
  let serialized: string;
  try {
    serialized = JSON.stringify(value);
  } catch {
    throw new ContentSecretGuardError('Credential sanitizer input is not JSON serializable.');
  }
  if (serialized === undefined) {
    throw new ContentSecretGuardError('Credential sanitizer input is not JSON serializable.');
  }
  const guarded = await sanitizeContentForImport(serialized, displayPath, options);
  try {
    return JSON.parse(guarded.content) as T;
  } catch {
    throw new ContentSecretGuardError('The configured credential sanitizer returned invalid structured content.');
  }
}

function spawnExternalSanitizer(command: string, displayPath: string) {
  return Bun.spawn({
    cmd: [command, 'sanitize-stdin', '--path', displayPath],
    stdin: 'pipe',
    stdout: 'pipe',
    stderr: 'pipe',
    env: process.env,
  });
}

type ExternalSanitizerProcess = ReturnType<typeof spawnExternalSanitizer>;

export const runExternalSanitizer: ExternalSanitizerRunner = async (
  command,
  content,
  displayPath,
): Promise<string> => {
  let proc: ExternalSanitizerProcess;
  try {
    proc = spawnExternalSanitizer(command, displayPath);
  } catch {
    throw new ContentSecretGuardError('The configured credential sanitizer could not be started.');
  }

  const timeout = setTimeout(() => {
    try {
      proc.kill(9);
    } catch {
      // The process already exited.
    }
  }, EXTERNAL_TIMEOUT_MS);

  try {
    proc.stdin.write(content);
    await proc.stdin.end();
    const [stdout, , exitCode] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
      proc.exited,
    ]);
    if (exitCode !== 0) {
      throw new ContentSecretGuardError(
        `The configured credential sanitizer failed closed (exit ${exitCode ?? 'signal'}).`,
      );
    }
    if (Buffer.byteLength(stdout, 'utf-8') > MAX_SANITIZED_BYTES) {
      throw new ContentSecretGuardError('The configured credential sanitizer returned an oversized payload.');
    }
    return stdout;
  } catch (error: unknown) {
    if (error instanceof ContentSecretGuardError) throw error;
    try {
      proc.kill(9);
    } catch {
      // The process already exited.
    }
    throw new ContentSecretGuardError('The configured credential sanitizer did not complete safely.');
  } finally {
    clearTimeout(timeout);
  }
};

export async function sanitizeContentForImport(
  content: string,
  displayPath: string,
  options: ContentSecretGuardOptions = {},
): Promise<ContentSecretGuardResult> {
  const native = redactFindings(content, { highEntropy: true });
  let sanitized = native.text;
  const command = (options.command ?? process.env.GBRAIN_CONTENT_SANITIZER ?? '').trim();
  const required = options.required ?? process.env.GBRAIN_CONTENT_SANITIZER_REQUIRED === '1';

  if (!command) {
    if (required) {
      throw new ContentSecretGuardError('Credential sanitizer is required but not configured.');
    }
    return {
      content: sanitized,
      changed: sanitized !== content,
      nativeRedactions: native.redactions.length,
      externalApplied: false,
    };
  }

  const runExternal = options.runExternal ?? runExternalSanitizer;
  try {
    sanitized = await runExternal(command, sanitized, displayPath);
  } catch (error: unknown) {
    if (error instanceof ContentSecretGuardError) throw error;
    throw new ContentSecretGuardError('The configured credential sanitizer did not complete safely.');
  }
  return {
    content: sanitized,
    changed: sanitized !== content,
    nativeRedactions: native.redactions.length,
    externalApplied: true,
  };
}
