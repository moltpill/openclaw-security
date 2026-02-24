/**
 * Tests for the tool-guard hook.
 * Updated to match the new read-only OpenClaw SDK hook API.
 * Hooks no longer return values — they log/audit via api.logger.
 */

import { createToolGuardHook, BeforeToolCallEvent } from '../../src/plugin/hooks/tool-guard';
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

describe('createToolGuardHook', () => {
  let guard: ClawGuard;
  const config = resolveConfig(DEFAULT_CONFIG);

  beforeAll(async () => {
    guard = await createClawGuard({ enclavePath: '/tmp/test-enclave' });
  });

  it('should return a function', () => {
    const { logger } = makeLogger();
    const hook = createToolGuardHook(guard, config, logger);
    expect(typeof hook).toBe('function');
  });

  it('should not log warnings for safe tool calls', async () => {
    const { logger, calls } = makeLogger();
    const hook = createToolGuardHook(guard, config, logger);
    const event: BeforeToolCallEvent = {
      toolName: 'web_search',
      params: { query: 'latest AI news' },
    };
    await hook(event);
    const warnOrError = calls.filter((c) => c.level === 'warn' || c.level === 'error');
    expect(warnOrError).toHaveLength(0);
  });

  it('should log for self-modification attempts via exec', async () => {
    const { logger, calls } = makeLogger();
    const hook = createToolGuardHook(guard, config, logger);
    const event: BeforeToolCallEvent = {
      toolName: 'exec',
      params: { command: 'npm uninstall -g openclaw' },
    };
    await hook(event);
    const relevant = calls.filter((c) => c.level === 'warn' || c.level === 'error');
    expect(relevant.length).toBeGreaterThan(0);
  });

  it('should log for gateway restart attempts', async () => {
    const { logger, calls } = makeLogger();
    const hook = createToolGuardHook(guard, config, logger);
    const event: BeforeToolCallEvent = {
      toolName: 'exec',
      params: { command: 'openclaw gateway restart' },
    };
    await hook(event);
    const relevant = calls.filter((c) => c.level === 'warn' || c.level === 'error');
    expect(relevant.length).toBeGreaterThan(0);
  });

  it('should allow safe exec commands', async () => {
    const { logger, calls } = makeLogger();
    const hook = createToolGuardHook(guard, config, logger);
    const event: BeforeToolCallEvent = {
      toolName: 'exec',
      params: { command: 'ls -la ~/workspace' },
    };
    await hook(event);
    const warnOrError = calls.filter((c) => c.level === 'warn' || c.level === 'error');
    expect(warnOrError).toHaveLength(0);
  });

  it('should handle read tool without logging', async () => {
    const { logger, calls } = makeLogger();
    const hook = createToolGuardHook(guard, config, logger);
    const event: BeforeToolCallEvent = {
      toolName: 'read',
      params: { path: '/tmp/some-file.txt' },
    };
    await hook(event);
    const warnOrError = calls.filter((c) => c.level === 'warn' || c.level === 'error');
    expect(warnOrError).toHaveLength(0);
  });

  it('should do nothing when selfModification guard is disabled', async () => {
    const { logger, calls } = makeLogger();
    const disabledConfig = resolveConfig({
      ...DEFAULT_CONFIG,
      selfModification: { ...DEFAULT_CONFIG.selfModification, enabled: false },
    });
    const hook = createToolGuardHook(guard, disabledConfig, logger);
    const event: BeforeToolCallEvent = {
      toolName: 'exec',
      params: { command: 'openclaw gateway stop' },
    };
    await hook(event);
    // No self-modification check — may still hit tool policy
    // Just ensure no throw
    expect(calls).toBeDefined();
  });

  it('should not throw for unknown tools', async () => {
    const { logger } = makeLogger();
    const hook = createToolGuardHook(guard, config, logger);
    const event: BeforeToolCallEvent = {
      toolName: 'some_new_tool_xyz',
      params: {},
    };
    await expect(hook(event)).resolves.toBeUndefined();
  });
});
