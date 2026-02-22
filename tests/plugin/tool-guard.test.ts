/**
 * Tool Guard Hook Tests
 */

import { createToolGuardHook, ToolHookContext } from '../../src/plugin/hooks/tool-guard';
import { ClawGuard } from '../../src/clawguard';
import { ClawGuardPluginConfig, DEFAULT_CONFIG } from '../../src/plugin/config';

describe('ToolGuardHook', () => {
  let mockGuard: Partial<ClawGuard>;
  let config: ClawGuardPluginConfig;

  beforeEach(() => {
    config = JSON.parse(JSON.stringify(DEFAULT_CONFIG));
    mockGuard = {
      checkSelfModification: jest.fn().mockReturnValue({
        blocked: false,
        requiresApproval: false,
        reason: '',
      }),
      checkTool: jest.fn().mockReturnValue({
        allowed: true,
        action: 'allow',
        reason: 'Policy allows this tool',
        requiresApproval: false,
      }),
    };
  });

  describe('self-modification checks', () => {
    it('should check exec commands for self-modification', async () => {
      const hook = createToolGuardHook(mockGuard as ClawGuard, config);

      const ctx: ToolHookContext = {
        tool: { name: 'exec' },
        args: { command: 'npm install some-package' },
      };

      const result = await hook(ctx);

      expect(mockGuard.checkSelfModification).toHaveBeenCalledWith(
        'npm install some-package',
        undefined
      );
      expect(result.continue).toBe(true);
    });

    it('should block dangerous self-modification attempts', async () => {
      mockGuard.checkSelfModification = jest.fn().mockReturnValue({
        blocked: true,
        requiresApproval: false,
        reason: 'Cannot modify agent installation',
        category: 'package-management',
      });

      const hook = createToolGuardHook(mockGuard as ClawGuard, config);

      const ctx: ToolHookContext = {
        tool: { name: 'exec' },
        args: { command: 'npm uninstall openclaw' },
      };

      const result = await hook(ctx);

      expect(result.continue).toBe(false);
      expect(result.error).toBeInstanceOf(Error);
      expect(result.error?.message).toContain('self-modification');
      expect(result.metadata?.clawguard).toMatchObject({
        selfModification: true,
        blocked: true,
      });
    });

    it('should request approval for self-modification when configured', async () => {
      config.selfModification.requireApproval = true;
      mockGuard.checkSelfModification = jest.fn().mockReturnValue({
        blocked: true,
        requiresApproval: true,
        reason: 'Gateway control requires approval',
        category: 'gateway-control',
      });

      const hook = createToolGuardHook(mockGuard as ClawGuard, config);

      const ctx: ToolHookContext = {
        tool: { name: 'exec' },
        args: { command: 'openclaw gateway restart' },
      };

      const result = await hook(ctx);

      expect(result.continue).toBe(false);
      expect(result.requestApproval).toBeDefined();
      expect(result.requestApproval?.type).toBe('self-modification');
      expect(result.requestApproval?.command).toBe('openclaw gateway restart');
      expect(result.requestApproval?.category).toBe('gateway-control');
    });

    it('should skip self-modification check when disabled', async () => {
      config.selfModification.enabled = false;

      const hook = createToolGuardHook(mockGuard as ClawGuard, config);

      const ctx: ToolHookContext = {
        tool: { name: 'exec' },
        args: { command: 'openclaw gateway stop' },
      };

      const result = await hook(ctx);

      expect(mockGuard.checkSelfModification).not.toHaveBeenCalled();
      expect(mockGuard.checkTool).toHaveBeenCalled();
    });

    it('should only check exec commands for self-modification', async () => {
      const hook = createToolGuardHook(mockGuard as ClawGuard, config);

      const ctx: ToolHookContext = {
        tool: { name: 'read' },
        args: { path: '/some/file.txt' },
      };

      await hook(ctx);

      expect(mockGuard.checkSelfModification).not.toHaveBeenCalled();
      expect(mockGuard.checkTool).toHaveBeenCalled();
    });
  });

  describe('tool policy checks', () => {
    it('should allow tools that pass policy check', async () => {
      const hook = createToolGuardHook(mockGuard as ClawGuard, config);

      const ctx: ToolHookContext = {
        tool: { name: 'read', action: 'file' },
        args: { path: '/workspace/readme.md' },
      };

      const result = await hook(ctx);

      expect(result.continue).toBe(true);
      expect(mockGuard.checkTool).toHaveBeenCalledWith(
        'read',
        'file',
        '/workspace/readme.md',
        undefined
      );
    });

    it('should block tools that fail policy check', async () => {
      mockGuard.checkTool = jest.fn().mockReturnValue({
        allowed: false,
        action: 'block',
        reason: 'Tool disabled by policy',
        requiresApproval: false,
      });

      const hook = createToolGuardHook(mockGuard as ClawGuard, config);

      const ctx: ToolHookContext = {
        tool: { name: 'browser' },
        args: { targetUrl: 'https://example.com' },
      };

      const result = await hook(ctx);

      expect(result.continue).toBe(false);
      expect(result.error).toBeInstanceOf(Error);
      expect(result.error?.message).toContain('blocked tool');
    });

    it('should request approval for tools requiring it', async () => {
      mockGuard.checkTool = jest.fn().mockReturnValue({
        allowed: false,
        action: 'require_approval',
        reason: 'Message sending requires approval',
        requiresApproval: true,
      });

      const hook = createToolGuardHook(mockGuard as ClawGuard, config);

      const ctx: ToolHookContext = {
        tool: { name: 'message', action: 'send' },
        args: { target: 'user@example.com', message: 'Hello' },
      };

      const result = await hook(ctx);

      expect(result.continue).toBe(false);
      expect(result.requestApproval).toBeDefined();
      expect(result.requestApproval?.type).toBe('tool-invocation');
      expect(result.requestApproval?.tool).toBe('message');
      expect(result.requestApproval?.action).toBe('send');
    });
  });

  describe('target extraction', () => {
    it('should extract path for read tool', async () => {
      const hook = createToolGuardHook(mockGuard as ClawGuard, config);

      await hook({
        tool: { name: 'read' },
        args: { path: '/some/file.txt' },
      });

      expect(mockGuard.checkTool).toHaveBeenCalledWith(
        'read',
        undefined,
        '/some/file.txt',
        undefined
      );
    });

    it('should extract file_path for write tool', async () => {
      const hook = createToolGuardHook(mockGuard as ClawGuard, config);

      await hook({
        tool: { name: 'write' },
        args: { file_path: '/some/file.txt', content: 'hello' },
      });

      expect(mockGuard.checkTool).toHaveBeenCalledWith(
        'write',
        undefined,
        '/some/file.txt',
        undefined
      );
    });

    it('should extract command for exec tool', async () => {
      const hook = createToolGuardHook(mockGuard as ClawGuard, config);

      await hook({
        tool: { name: 'exec' },
        args: { command: 'ls -la' },
      });

      expect(mockGuard.checkTool).toHaveBeenCalledWith(
        'exec',
        undefined,
        'ls -la',
        undefined
      );
    });

    it('should extract targetUrl for browser tool', async () => {
      const hook = createToolGuardHook(mockGuard as ClawGuard, config);

      await hook({
        tool: { name: 'browser' },
        args: { targetUrl: 'https://example.com' },
      });

      expect(mockGuard.checkTool).toHaveBeenCalledWith(
        'browser',
        undefined,
        'https://example.com',
        undefined
      );
    });

    it('should extract target for message tool', async () => {
      const hook = createToolGuardHook(mockGuard as ClawGuard, config);

      await hook({
        tool: { name: 'message' },
        args: { target: 'user123', message: 'hello' },
      });

      expect(mockGuard.checkTool).toHaveBeenCalledWith(
        'message',
        undefined,
        'user123',
        undefined
      );
    });
  });

  describe('session tracking', () => {
    it('should pass session ID to all checks', async () => {
      const hook = createToolGuardHook(mockGuard as ClawGuard, config);

      const ctx: ToolHookContext = {
        tool: { name: 'exec' },
        args: { command: 'echo test' },
        session: { id: 'session-xyz' },
      };

      await hook(ctx);

      expect(mockGuard.checkSelfModification).toHaveBeenCalledWith(
        'echo test',
        'session-xyz'
      );
      expect(mockGuard.checkTool).toHaveBeenCalledWith(
        'exec',
        undefined,
        'echo test',
        'session-xyz'
      );
    });
  });
});
