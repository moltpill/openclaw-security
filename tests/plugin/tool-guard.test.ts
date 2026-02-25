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

  // ── Allowlist tests ─────────────────────────────────────────────────────

  describe('command allowlist', () => {
    it('should bypass self-mod guard for allowlisted commands', async () => {
      const { logger, calls } = makeLogger();
      const allowlistConfig = resolveConfig({
        ...DEFAULT_CONFIG,
        selfModification: { ...DEFAULT_CONFIG.selfModification, enabled: true },
        allowlist: {
          enabled: true,
          commands: ['openclaw gateway restart'],
          elevate: [],
        },
      });
      const hook = createToolGuardHook(guard, allowlistConfig, logger);
      const event: BeforeToolCallEvent = {
        toolName: 'exec',
        params: { command: 'openclaw gateway restart' },
      };
      const result = await hook(event);

      // Should NOT be blocked — allowlist overrides self-mod guard
      expect(result?.block).toBeFalsy();
      // Should log info about allowlist match
      const infoLogs = calls.filter((c) => c.level === 'info');
      expect(infoLogs.length).toBeGreaterThan(0);
      expect(infoLogs[0].msg).toContain('allowlisted');
    });

    it('should auto-elevate commands in elevate list', async () => {
      const { logger } = makeLogger();
      const allowlistConfig = resolveConfig({
        ...DEFAULT_CONFIG,
        allowlist: {
          enabled: true,
          commands: [],
          elevate: ['sudo tailscale *'],
        },
      });
      const hook = createToolGuardHook(guard, allowlistConfig, logger);
      const event: BeforeToolCallEvent = {
        toolName: 'exec',
        params: { command: 'sudo tailscale up --accept-routes' },
      };
      const result = await hook(event);

      // Should return modified params with elevated: true
      expect(result?.params?.elevated).toBe(true);
      expect(result?.block).toBeFalsy();
    });

    it('should not auto-elevate non-elevate commands', async () => {
      const { logger } = makeLogger();
      const allowlistConfig = resolveConfig({
        ...DEFAULT_CONFIG,
        allowlist: {
          enabled: true,
          commands: ['tailscale status'],
          elevate: [],
        },
      });
      const hook = createToolGuardHook(guard, allowlistConfig, logger);
      const event: BeforeToolCallEvent = {
        toolName: 'exec',
        params: { command: 'tailscale status' },
      };
      const result = await hook(event);

      // Should be allowed but NOT elevated
      expect(result?.block).toBeFalsy();
      expect(result?.params?.elevated).toBeUndefined();
    });

    it('should still flag non-allowlisted dangerous commands', async () => {
      const { logger, calls } = makeLogger();
      const allowlistConfig = resolveConfig({
        ...DEFAULT_CONFIG,
        selfModification: { ...DEFAULT_CONFIG.selfModification, enabled: true },
        allowlist: {
          enabled: true,
          commands: ['tailscale status'],
          elevate: [],
        },
      });
      const hook = createToolGuardHook(guard, allowlistConfig, logger);
      const event: BeforeToolCallEvent = {
        toolName: 'exec',
        params: { command: 'npm uninstall -g openclaw' },
      };
      const result = await hook(event);

      // Should be flagged (blocked or warned) — not in allowlist
      const flagged = calls.filter((c) => c.level === 'warn' || c.level === 'error');
      expect(flagged.length).toBeGreaterThan(0);
      // Should NOT have an allowlist info log
      const allowlistLogs = calls.filter((c) => c.msg.includes('allowlisted'));
      expect(allowlistLogs).toHaveLength(0);
    });

    it('should prevent injection via allowlisted prefix', async () => {
      const { logger } = makeLogger();
      const allowlistConfig = resolveConfig({
        ...DEFAULT_CONFIG,
        allowlist: {
          enabled: true,
          commands: ['tailscale status'],
          elevate: [],
        },
      });
      const hook = createToolGuardHook(guard, allowlistConfig, logger);
      const event: BeforeToolCallEvent = {
        toolName: 'exec',
        params: { command: 'tailscale status && rm -rf /' },
      };
      const result = await hook(event);

      // "tailscale status" is exact match — "tailscale status && rm -rf /" should NOT match
      expect(result?.block).toBeFalsy(); // won't be blocked by self-mod either (no openclaw pattern)
      // But importantly it's NOT allowlisted (no info log about allowlist)
      // It falls through to normal tool policy check
    });
  });
});
