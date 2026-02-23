/**
 * File Watch Hook Tests
 *
 * Updated to match the current OpenClaw SDK-aligned implementation.
 *
 * The hook now:
 *   - Takes (event: BeforeToolCallEvent, ctx?) and 3 constructor args (guard, config, logger)
 *   - Returns PluginHookBeforeToolCallResult | void
 *   - Hard-block violations return { block: true, blockReason }
 *   - Soft violations (requireApproval / warn) log via logger and return void
 */

import { createFileWatchHook, BeforeToolCallEvent } from '../../src/plugin/hooks/file-watch';
import { ClawGuard } from '../../src/clawguard';
import { ClawGuardPluginConfig, DEFAULT_CONFIG, resolveConfig } from '../../src/plugin/config';
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
  let mockGuard: Partial<ClawGuard>;
  let config: ClawGuardPluginConfig;

  beforeEach(() => {
    config = resolveConfig(DEFAULT_CONFIG);
    mockGuard = {
      isProtectedFile: jest.fn().mockReturnValue(false),
      scanContent: jest.fn().mockReturnValue({
        safe: true,
        action: 'allow',
      }),
    };
  });

  // ── Enclave protection ────────────────────────────────────────────────────

  describe('enclave protection', () => {
    it('should hard-block writes to protected files when requireApproval=false', async () => {
      config.enclave.enabled = true;
      config.enclave.requireApproval = false;
      mockGuard.isProtectedFile = jest.fn().mockReturnValue(true);

      const { logger, calls } = makeLogger();
      const hook = createFileWatchHook(mockGuard as ClawGuard, config, logger);

      const event: BeforeToolCallEvent = {
        toolName: 'write',
        params: { path: '/workspace/SOUL.md', content: 'New content' },
      };

      const result = await hook(event);

      expect(result?.block).toBe(true);
      expect(result?.blockReason).toContain('SOUL.md');
      const errorLogs = calls.filter((c) => c.level === 'error');
      expect(errorLogs.length).toBeGreaterThan(0);
    });

    it('should warn but allow writes to protected files when requireApproval=true', async () => {
      config.enclave.enabled = true;
      config.enclave.requireApproval = true;
      mockGuard.isProtectedFile = jest.fn().mockReturnValue(true);

      const { logger, calls } = makeLogger();
      const hook = createFileWatchHook(mockGuard as ClawGuard, config, logger);

      const event: BeforeToolCallEvent = {
        toolName: 'write',
        params: { path: '/workspace/MEMORY.md', content: 'Updated memory' },
      };

      const result = await hook(event);

      // Not blocked — approval flow handles it
      expect(result?.block).toBeFalsy();
      const warnLogs = calls.filter((c) => c.level === 'warn');
      expect(warnLogs.length).toBeGreaterThan(0);
      expect(warnLogs[0].msg).toContain('MEMORY.md');
    });

    it('should allow writes to unprotected files', async () => {
      config.enclave.enabled = true;
      mockGuard.isProtectedFile = jest.fn().mockReturnValue(false);

      const { logger, calls } = makeLogger();
      const hook = createFileWatchHook(mockGuard as ClawGuard, config, logger);

      const event: BeforeToolCallEvent = {
        toolName: 'write',
        params: { path: '/workspace/project/code.ts', content: 'const x = 1;' },
      };

      const result = await hook(event);

      expect(result?.block).toBeFalsy();
      const errorLogs = calls.filter((c) => c.level === 'error');
      expect(errorLogs).toHaveLength(0);
    });

    it('should skip enclave check when disabled', async () => {
      config.enclave.enabled = false;
      mockGuard.isProtectedFile = jest.fn().mockReturnValue(true);

      const { logger } = makeLogger();
      const hook = createFileWatchHook(mockGuard as ClawGuard, config, logger);

      const event: BeforeToolCallEvent = {
        toolName: 'write',
        params: { path: '/workspace/SOUL.md', content: 'New content' },
      };

      await hook(event);

      // isProtectedFile should never be called when enclave is disabled
      expect(mockGuard.isProtectedFile).not.toHaveBeenCalled();
    });

    it('should not block read operations on protected files', async () => {
      config.enclave.enabled = true;
      config.enclave.requireApproval = false;
      mockGuard.isProtectedFile = jest.fn().mockReturnValue(true);

      const { logger } = makeLogger();
      const hook = createFileWatchHook(mockGuard as ClawGuard, config, logger);

      // read is not a write operation
      const event: BeforeToolCallEvent = {
        toolName: 'read',
        params: { path: '/workspace/SOUL.md' },
      };

      const result = await hook(event);

      // Reads are not gated by the enclave check
      expect(result?.block).toBeFalsy();
    });
  });

  // ── Secret scanning ───────────────────────────────────────────────────────

  describe('secret scanning', () => {
    it('should block writes containing secrets when onDetection=block', async () => {
      config.scanner.enabled = true;
      config.scanner.onDetection = 'block';
      mockGuard.scanContent = jest.fn().mockReturnValue({
        safe: false,
        action: 'block',
      });

      const { logger, calls } = makeLogger();
      const hook = createFileWatchHook(mockGuard as ClawGuard, config, logger);

      const event: BeforeToolCallEvent = {
        toolName: 'write',
        params: { path: '/workspace/config.json', content: '{ "apiKey": "sk-abc123secret" }' },
      };

      const result = await hook(event);

      expect(result?.block).toBe(true);
      expect(result?.blockReason).toContain('secrets');
      const errorLogs = calls.filter((c) => c.level === 'error');
      expect(errorLogs.length).toBeGreaterThan(0);
    });

    it('should warn but allow when onDetection=warn', async () => {
      config.scanner.enabled = true;
      config.scanner.onDetection = 'warn';
      mockGuard.scanContent = jest.fn().mockReturnValue({
        safe: false,
        action: 'warn',
      });

      const { logger, calls } = makeLogger();
      const hook = createFileWatchHook(mockGuard as ClawGuard, config, logger);

      const event: BeforeToolCallEvent = {
        toolName: 'write',
        params: { path: '/workspace/config.json', content: '{ "apiKey": "sk-abc123" }' },
      };

      const result = await hook(event);

      expect(result?.block).toBeFalsy();
      const warnLogs = calls.filter((c) => c.level === 'warn');
      expect(warnLogs.length).toBeGreaterThan(0);
    });

    it('should warn but allow when onDetection=redact', async () => {
      config.scanner.enabled = true;
      config.scanner.onDetection = 'redact';
      mockGuard.scanContent = jest.fn().mockReturnValue({
        safe: false,
        action: 'warn',
        redactedContent: '{ "apiKey": "[REDACTED]" }',
      });

      const { logger, calls } = makeLogger();
      const hook = createFileWatchHook(mockGuard as ClawGuard, config, logger);

      const event: BeforeToolCallEvent = {
        toolName: 'write',
        params: { path: '/workspace/config.json', content: '{ "apiKey": "sk-abc123secret" }' },
      };

      const result = await hook(event);

      expect(result?.block).toBeFalsy();
      // Should log a warn about would-have-been-redacted
      const warnLogs = calls.filter((c) => c.level === 'warn');
      expect(warnLogs.length).toBeGreaterThan(0);
    });

    it('should allow without warning when onDetection=allow', async () => {
      config.scanner.enabled = true;
      config.scanner.onDetection = 'allow';
      mockGuard.scanContent = jest.fn().mockReturnValue({
        safe: false,
        action: 'allow',
      });

      const { logger, calls } = makeLogger();
      const hook = createFileWatchHook(mockGuard as ClawGuard, config, logger);

      const event: BeforeToolCallEvent = {
        toolName: 'write',
        params: { path: '/workspace/config.json', content: '{ "apiKey": "sk-abc123" }' },
      };

      const result = await hook(event);

      expect(result?.block).toBeFalsy();
      const warnOrError = calls.filter((c) => c.level === 'warn' || c.level === 'error');
      expect(warnOrError).toHaveLength(0);
    });

    it('should skip secret scanning when disabled', async () => {
      config.scanner.enabled = false;

      const { logger } = makeLogger();
      const hook = createFileWatchHook(mockGuard as ClawGuard, config, logger);

      const event: BeforeToolCallEvent = {
        toolName: 'write',
        params: { path: '/workspace/config.json', content: '{ "apiKey": "sk-abc123" }' },
      };

      await hook(event);

      expect(mockGuard.scanContent).not.toHaveBeenCalled();
    });

    it('should not scan read tools for secrets', async () => {
      config.scanner.enabled = true;
      config.scanner.onDetection = 'block';
      mockGuard.scanContent = jest.fn().mockReturnValue({
        safe: false,
        action: 'block',
      });

      const { logger } = makeLogger();
      const hook = createFileWatchHook(mockGuard as ClawGuard, config, logger);

      // read tool has no 'content' param — isWriteOperation returns false
      const event: BeforeToolCallEvent = {
        toolName: 'read',
        params: { path: '/workspace/config.json' },
      };

      const result = await hook(event);

      // Secret scanner is not triggered for reads
      expect(mockGuard.scanContent).not.toHaveBeenCalled();
      expect(result?.block).toBeFalsy();
    });
  });

  // ── Combined protection ───────────────────────────────────────────────────

  describe('combined protection', () => {
    it('should check enclave before secret scanning', async () => {
      config.enclave.enabled = true;
      config.scanner.enabled = true;
      config.enclave.requireApproval = false; // hard block on protected writes
      mockGuard.isProtectedFile = jest.fn().mockReturnValue(true);
      mockGuard.scanContent = jest.fn().mockReturnValue({ safe: false, action: 'block' });

      const { logger } = makeLogger();
      const hook = createFileWatchHook(mockGuard as ClawGuard, config, logger);

      const event: BeforeToolCallEvent = {
        toolName: 'write',
        params: { path: '/workspace/SOUL.md', content: 'Content with apiKey: sk-secret' },
      };

      const result = await hook(event);

      // Blocked at enclave step — scanner not reached
      expect(result?.block).toBe(true);
      expect(mockGuard.scanContent).not.toHaveBeenCalled();
    });

    it('should scan secrets for unprotected file writes', async () => {
      config.enclave.enabled = true;
      config.scanner.enabled = true;
      config.scanner.onDetection = 'warn';
      mockGuard.isProtectedFile = jest.fn().mockReturnValue(false);
      mockGuard.scanContent = jest.fn().mockReturnValue({ safe: false, action: 'warn' });

      const { logger, calls } = makeLogger();
      const hook = createFileWatchHook(mockGuard as ClawGuard, config, logger);

      const event: BeforeToolCallEvent = {
        toolName: 'write',
        params: { path: '/workspace/project/config.json', content: 'apiKey: sk-secret' },
      };

      await hook(event);

      expect(mockGuard.isProtectedFile).toHaveBeenCalledWith('/workspace/project/config.json');
      expect(mockGuard.scanContent).toHaveBeenCalledWith('apiKey: sk-secret', 'write');
      const warnLogs = calls.filter((c) => c.level === 'warn');
      expect(warnLogs.length).toBeGreaterThan(0);
    });
  });

  // ── Edit tool ─────────────────────────────────────────────────────────────

  describe('edit tool handling', () => {
    it('should treat edit as a write operation for enclave check', async () => {
      config.enclave.enabled = true;
      config.enclave.requireApproval = false;
      mockGuard.isProtectedFile = jest.fn().mockReturnValue(true);

      const { logger } = makeLogger();
      const hook = createFileWatchHook(mockGuard as ClawGuard, config, logger);

      const event: BeforeToolCallEvent = {
        toolName: 'edit',
        params: { path: '/workspace/SOUL.md', old_string: 'old', new_string: 'new' },
      };

      const result = await hook(event);

      expect(result?.block).toBe(true);
    });
  });

  // ── No-op path ────────────────────────────────────────────────────────────

  describe('no-op path', () => {
    it('should return void with no logs for safe operations', async () => {
      const { logger, calls } = makeLogger();
      const hook = createFileWatchHook(mockGuard as ClawGuard, config, logger);

      const event: BeforeToolCallEvent = {
        toolName: 'write',
        params: { path: '/workspace/project/safe.ts', content: 'export const x = 1;' },
      };

      const result = await hook(event);

      expect(result?.block).toBeFalsy();
      const warnOrError = calls.filter((c) => c.level === 'warn' || c.level === 'error');
      expect(warnOrError).toHaveLength(0);
    });
  });
});
