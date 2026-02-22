/**
 * File Watch Hook Tests
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { createFileWatchHook, FileHookContext } from '../../src/plugin/hooks/file-watch';
import { ClawGuard } from '../../src/clawguard';
import { ClawGuardPluginConfig, DEFAULT_CONFIG } from '../../src/plugin/config';

describe('FileWatchHook', () => {
  let mockGuard: Partial<ClawGuard>;
  let config: ClawGuardPluginConfig;

  beforeEach(() => {
    config = { ...DEFAULT_CONFIG };
    mockGuard = {
      isProtectedFile: vi.fn().mockReturnValue(false),
      scanContent: vi.fn().mockReturnValue({
        safe: true,
        action: 'allow',
      }),
    };
  });

  describe('enclave protection', () => {
    it('should block writes to protected files without approval', async () => {
      config.enclave.enabled = true;
      config.enclave.requireApproval = false;
      mockGuard.isProtectedFile = vi.fn().mockReturnValue(true);

      const hook = createFileWatchHook(mockGuard as ClawGuard, config);

      const ctx: FileHookContext = {
        operation: 'write',
        path: '/workspace/SOUL.md',
        content: 'New content',
      };

      const result = await hook(ctx);

      expect(result.continue).toBe(false);
      expect(result.error).toBeInstanceOf(Error);
      expect(result.error?.message).toContain('protected file');
      expect(result.metadata?.clawguard).toMatchObject({
        enclave: true,
        protected: true,
        blocked: true,
      });
    });

    it('should request approval for writes to protected files when configured', async () => {
      config.enclave.enabled = true;
      config.enclave.requireApproval = true;
      mockGuard.isProtectedFile = vi.fn().mockReturnValue(true);

      const hook = createFileWatchHook(mockGuard as ClawGuard, config);

      const ctx: FileHookContext = {
        operation: 'write',
        path: '/workspace/MEMORY.md',
        content: 'Updated memory',
      };

      const result = await hook(ctx);

      expect(result.continue).toBe(false);
      expect(result.requestApproval).toBeDefined();
      expect(result.requestApproval?.type).toBe('enclave-write');
      expect(result.requestApproval?.path).toBe('/workspace/MEMORY.md');
      expect(result.requestApproval?.content).toBe('Updated memory');
    });

    it('should block deletes to protected files', async () => {
      config.enclave.enabled = true;
      mockGuard.isProtectedFile = vi.fn().mockReturnValue(true);

      const hook = createFileWatchHook(mockGuard as ClawGuard, config);

      const ctx: FileHookContext = {
        operation: 'delete',
        path: '/workspace/secrets/api-keys.json',
      };

      const result = await hook(ctx);

      expect(result.continue).toBe(false);
      expect(result.requestApproval || result.error).toBeDefined();
    });

    it('should allow writes to unprotected files', async () => {
      config.enclave.enabled = true;
      mockGuard.isProtectedFile = vi.fn().mockReturnValue(false);

      const hook = createFileWatchHook(mockGuard as ClawGuard, config);

      const ctx: FileHookContext = {
        operation: 'write',
        path: '/workspace/project/code.ts',
        content: 'const x = 1;',
      };

      const result = await hook(ctx);

      expect(result.continue).toBe(true);
    });

    it('should skip enclave check when disabled', async () => {
      config.enclave.enabled = false;
      mockGuard.isProtectedFile = vi.fn().mockReturnValue(true);

      const hook = createFileWatchHook(mockGuard as ClawGuard, config);

      const ctx: FileHookContext = {
        operation: 'write',
        path: '/workspace/SOUL.md',
        content: 'New content',
      };

      const result = await hook(ctx);

      // Should proceed to scanner check, not blocked by enclave
      expect(mockGuard.isProtectedFile).not.toHaveBeenCalled();
    });
  });

  describe('secret scanning', () => {
    it('should block writes containing secrets when onDetection is block', async () => {
      config.scanner.enabled = true;
      config.scanner.onDetection = 'block';
      mockGuard.scanContent = vi.fn().mockReturnValue({
        safe: false,
        action: 'block',
      });

      const hook = createFileWatchHook(mockGuard as ClawGuard, config);

      const ctx: FileHookContext = {
        operation: 'write',
        path: '/workspace/config.json',
        content: '{ "apiKey": "sk-abc123secret" }',
      };

      const result = await hook(ctx);

      expect(result.continue).toBe(false);
      expect(result.error).toBeInstanceOf(Error);
      expect(result.error?.message).toContain('contains secrets');
    });

    it('should redact secrets when onDetection is redact', async () => {
      config.scanner.enabled = true;
      config.scanner.onDetection = 'redact';
      mockGuard.scanContent = vi.fn().mockReturnValue({
        safe: false,
        action: 'warn',
        redactedContent: '{ "apiKey": "[REDACTED]" }',
      });

      const hook = createFileWatchHook(mockGuard as ClawGuard, config);

      const ctx: FileHookContext = {
        operation: 'write',
        path: '/workspace/config.json',
        content: '{ "apiKey": "sk-abc123secret" }',
      };

      const result = await hook(ctx);

      expect(result.continue).toBe(true);
      expect(result.context?.content).toBe('{ "apiKey": "[REDACTED]" }');
      expect(result.warning).toContain('redacted');
    });

    it('should warn but allow when onDetection is warn', async () => {
      config.scanner.enabled = true;
      config.scanner.onDetection = 'warn';
      mockGuard.scanContent = vi.fn().mockReturnValue({
        safe: false,
        action: 'warn',
      });

      const hook = createFileWatchHook(mockGuard as ClawGuard, config);

      const ctx: FileHookContext = {
        operation: 'write',
        path: '/workspace/config.json',
        content: '{ "apiKey": "sk-abc123" }',
      };

      const result = await hook(ctx);

      expect(result.continue).toBe(true);
      expect(result.warning).toContain('secrets');
    });

    it('should allow without warning when onDetection is allow', async () => {
      config.scanner.enabled = true;
      config.scanner.onDetection = 'allow';
      mockGuard.scanContent = vi.fn().mockReturnValue({
        safe: false,
        action: 'allow',
      });

      const hook = createFileWatchHook(mockGuard as ClawGuard, config);

      const ctx: FileHookContext = {
        operation: 'write',
        path: '/workspace/config.json',
        content: '{ "apiKey": "sk-abc123" }',
      };

      const result = await hook(ctx);

      expect(result.continue).toBe(true);
      expect(result.warning).toBeUndefined();
    });

    it('should skip secret scanning when disabled', async () => {
      config.scanner.enabled = false;

      const hook = createFileWatchHook(mockGuard as ClawGuard, config);

      const ctx: FileHookContext = {
        operation: 'write',
        path: '/workspace/config.json',
        content: '{ "apiKey": "sk-abc123" }',
      };

      const result = await hook(ctx);

      expect(mockGuard.scanContent).not.toHaveBeenCalled();
      expect(result.continue).toBe(true);
    });

    it('should not scan reads for blocking', async () => {
      config.scanner.enabled = true;

      const hook = createFileWatchHook(mockGuard as ClawGuard, config);

      const ctx: FileHookContext = {
        operation: 'read',
        path: '/workspace/config.json',
      };

      const result = await hook(ctx);

      // Reads should pass through with metadata indicating will-scan
      expect(result.continue).toBe(true);
      expect(result.metadata?.clawguard?.willScan).toBe(true);
    });
  });

  describe('combined protection', () => {
    it('should check enclave before secret scanning', async () => {
      config.enclave.enabled = true;
      config.scanner.enabled = true;
      config.enclave.requireApproval = true;
      mockGuard.isProtectedFile = vi.fn().mockReturnValue(true);

      const hook = createFileWatchHook(mockGuard as ClawGuard, config);

      const ctx: FileHookContext = {
        operation: 'write',
        path: '/workspace/SOUL.md',
        content: 'Content with apiKey: sk-secret',
      };

      const result = await hook(ctx);

      // Should stop at enclave check, not proceed to scanner
      expect(result.continue).toBe(false);
      expect(result.requestApproval?.type).toBe('enclave-write');
      expect(mockGuard.scanContent).not.toHaveBeenCalled();
    });

    it('should scan secrets for unprotected writes', async () => {
      config.enclave.enabled = true;
      config.scanner.enabled = true;
      config.scanner.onDetection = 'warn';
      mockGuard.isProtectedFile = vi.fn().mockReturnValue(false);
      mockGuard.scanContent = vi.fn().mockReturnValue({
        safe: false,
        action: 'warn',
      });

      const hook = createFileWatchHook(mockGuard as ClawGuard, config);

      const ctx: FileHookContext = {
        operation: 'write',
        path: '/workspace/project/config.json',
        content: 'apiKey: sk-secret',
      };

      const result = await hook(ctx);

      expect(mockGuard.isProtectedFile).toHaveBeenCalledWith('/workspace/project/config.json');
      expect(mockGuard.scanContent).toHaveBeenCalledWith('apiKey: sk-secret', 'write');
      expect(result.warning).toBeDefined();
    });
  });

  describe('metadata', () => {
    it('should attach metadata for allowed operations', async () => {
      const hook = createFileWatchHook(mockGuard as ClawGuard, config);

      const ctx: FileHookContext = {
        operation: 'write',
        path: '/workspace/file.txt',
        content: 'Safe content',
      };

      const result = await hook(ctx);

      expect(result.metadata?.clawguard).toMatchObject({
        checked: true,
        operation: 'write',
      });
    });
  });
});
