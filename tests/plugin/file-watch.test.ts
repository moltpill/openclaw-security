/**
 * Tests for the file-watch hook.
 * Updated to match the new read-only OpenClaw SDK hook API.
 * Hooks no longer return values — they log/audit via api.logger.
 */

import { createFileWatchHook, BeforeToolCallEvent } from '../../src/plugin/hooks/file-watch';
import { ClawGuard, createClawGuard } from '../../src/clawguard';
import { DEFAULT_CONFIG, resolveConfig } from '../../src/plugin/config';
import type { PluginLogger } from '../../src/plugin/sdk-types';

function makeLogger(): { logger: PluginLogger; calls: { level: string; msg: string }[] } {
  const calls: { level: string; msg: string }[] = [];
  const logger: PluginLogger = {
    debug: (msg) => calls.push({ level: 'debug', msg }),
    info: (msg) => calls.push({ level: 'info', msg }),
    warn: (msg) => calls.push({ level: 'warn', msg }),
    error: (msg) => calls.push({ level: 'error', msg }),
  };
  return { logger, calls };
}

describe('createFileWatchHook', () => {
  let guard: ClawGuard;
  const config = resolveConfig(DEFAULT_CONFIG);

  beforeAll(async () => {
    guard = await createClawGuard({ enclavePath: '/tmp/test-enclave' });
  });

  it('should return a function', () => {
    const { logger } = makeLogger();
    const hook = createFileWatchHook(guard, config, logger);
    expect(typeof hook).toBe('function');
  });

  it('should not log warnings for non-file tools', async () => {
    const { logger, calls } = makeLogger();
    const hook = createFileWatchHook(guard, config, logger);
    const event: BeforeToolCallEvent = {
      toolName: 'web_search',
      params: { query: 'hello world' },
    };
    await hook(event);
    const warnOrError = calls.filter((c) => c.level === 'warn' || c.level === 'error');
    expect(warnOrError).toHaveLength(0);
  });

  it('should not log warnings for safe file reads', async () => {
    const { logger, calls } = makeLogger();
    const hook = createFileWatchHook(guard, config, logger);
    const event: BeforeToolCallEvent = {
      toolName: 'read',
      params: { path: '/tmp/safe-file.txt' },
    };
    await hook(event);
    const warnOrError = calls.filter((c) => c.level === 'warn' || c.level === 'error');
    expect(warnOrError).toHaveLength(0);
  });

  it('should log when writing to a protected enclave file', async () => {
    const { logger, calls } = makeLogger();
    // Add SOUL.md to enclave protected list
    const protectedConfig = resolveConfig({
      ...DEFAULT_CONFIG,
      enclave: {
        ...DEFAULT_CONFIG.enclave,
        protectedFiles: ['SOUL.md', 'MEMORY.md'],
      },
    });
    const hook = createFileWatchHook(guard, protectedConfig, logger);
    const event: BeforeToolCallEvent = {
      toolName: 'write',
      params: { path: '/workspace/SOUL.md', content: 'new content' },
    };
    await hook(event);
    // Should have logged a warning or error about protected file
    const relevant = calls.filter((c) => c.level === 'warn' || c.level === 'error');
    expect(relevant.length).toBeGreaterThan(0);
  });

  it('should handle edit tool with file path', async () => {
    const { logger } = makeLogger();
    const hook = createFileWatchHook(guard, config, logger);
    const event: BeforeToolCallEvent = {
      toolName: 'edit',
      params: { file_path: '/tmp/test.ts', old_string: 'foo', new_string: 'bar' },
    };
    await expect(hook(event)).resolves.toBeUndefined();
  });

  it('should do nothing when enclave is disabled', async () => {
    const { logger, calls } = makeLogger();
    const disabledConfig = resolveConfig({
      ...DEFAULT_CONFIG,
      enclave: {
        ...DEFAULT_CONFIG.enclave,
        enabled: false,
        protectedFiles: ['SOUL.md', 'MEMORY.md'],
      },
    });
    const hook = createFileWatchHook(guard, disabledConfig, logger);
    const event: BeforeToolCallEvent = {
      toolName: 'write',
      params: { path: '/workspace/SOUL.md', content: 'overwrite' },
    };
    await hook(event);
    const warnOrError = calls.filter((c) => c.level === 'warn' || c.level === 'error');
    expect(warnOrError).toHaveLength(0);
  });

  it('should not throw for events with no path param', async () => {
    const { logger } = makeLogger();
    const hook = createFileWatchHook(guard, config, logger);
    const event: BeforeToolCallEvent = {
      toolName: 'write',
      params: {},
    };
    await expect(hook(event)).resolves.toBeUndefined();
  });
});
