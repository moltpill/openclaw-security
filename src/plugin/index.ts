/**
 * ClawGuard OpenClaw Plugin
 *
 * Security layer for OpenClaw agents - injection detection,
 * secret scanning, enclave protection, and audit logging.
 *
 * Compatible with: OpenClaw plugin SDK (openclaw/plugin-sdk)
 *
 * HOOK NOTES (important for maintainers):
 * ----------------------------------------
 * The OpenClaw plugin SDK exposes typed lifecycle hooks via api.on().
 *
 * BLOCKING:
 *   before_tool_call is a modifying hook. Return { block: true, blockReason }
 *   and OpenClaw will prevent the tool from executing. ClawGuard uses this
 *   for hard-block violations (self-modification, enclave writes, secret leaks).
 *
 *   message_received is fire-and-forget — blocking at the message level
 *   requires a future SDK update (tracked in openclaw/openclaw#TODO).
 *
 * Hook mapping:
 *   message:before (old) → message_received
 *   tool:before    (old) → before_tool_call
 *   file:before    (old) → before_tool_call (filtered for file tools)
 */

import type { OpenClawPluginApi } from './sdk-types';
import { ClawGuard, createClawGuard } from '../clawguard';
import {
  ClawGuardPluginConfigSchema,
  ClawGuardPluginConfig,
  ClawGuardPluginConfigInput,
  DEFAULT_CONFIG,
  resolveConfig,
  applyWorkspaceDetection,
} from './config';
import { registerCli } from './cli';
import { createMessageShieldHook } from './hooks/message-shield';
import { createToolGuardHook } from './hooks/tool-guard';
import { createFileWatchHook } from './hooks/file-watch';

/**
 * Plugin registration result
 */
export interface PluginRegistrationResult {
  success: boolean;
  guard: ClawGuard;
}

/**
 * ClawGuard OpenClaw Plugin Definition
 */
export const clawguardPlugin = {
  /** Unique plugin identifier */
  id: 'clawguard',

  /** Human-readable name */
  name: 'ClawGuard Security',

  /** Plugin description */
  description:
    'Security layer for OpenClaw agents - injection detection, secret scanning, enclave protection, and audit logging',

  /** Plugin version */
  version: '0.1.0',

  /** Configuration schema for validation */
  configSchema: ClawGuardPluginConfigSchema,

  /**
   * Register the plugin with OpenClaw
   */
  async register(api: OpenClawPluginApi): Promise<void> {
    // Get plugin-specific config (api.pluginConfig replaces old api.getConfig())
    const userConfig = (api.pluginConfig ?? {}) as ClawGuardPluginConfigInput;
    let config = resolveConfig(userConfig);

    // Resolve workspace path (api.resolvePath replaces old api.getWorkspacePath())
    const workspacePath =
      (api.config as Record<string, unknown> & { workspace?: { dir?: string } }).workspace?.dir ??
      api.resolvePath('.') ??
      (process.env['HOME'] ?? '') + '/.openclaw/workspace';

    config = applyWorkspaceDetection(config, workspacePath);

    // Register CLI commands via the plugin api
    registerCli(api as unknown as Parameters<typeof registerCli>[0]);

    api.logger.info('ClawGuard initializing...', { config });

    // Create ClawGuard instance
    const guard = await createClawGuard({ enclavePath: workspacePath });

    // ── message_received hook ─────────────────────────────────────────────
    // Scans every inbound message for prompt injection.
    // Fire-and-forget: logs/audits findings. The message_received hook
    // does not support blocking in the current SDK.
    api.on('message_received', async (event, ctx) => {
      const handler = createMessageShieldHook(guard, config, api.logger);
      await handler(event, ctx);
    });

    // ── before_tool_call hook ─────────────────────────────────────────────
    // Guards tool invocations and protects enclave files.
    // Returns { block: true, blockReason } for hard-block violations.
    // The SDK collects this result and prevents the tool from executing.
    api.on('before_tool_call', async (event, ctx) => {
      // Tool guard (self-modification + policy check)
      const toolHandler = createToolGuardHook(guard, config, api.logger);
      const toolResult = await toolHandler(event, ctx);
      // Propagate block immediately — no point checking file watch if tool is blocked
      if (toolResult?.block) return toolResult;

      // File watch (enclave + secret scanner) for file-related tools
      const FILE_TOOLS = new Set(['exec', 'read', 'write', 'edit', 'bash', 'read_file', 'write_file']);
      if (FILE_TOOLS.has(event.toolName)) {
        const fileHandler = createFileWatchHook(guard, config, api.logger);
        return fileHandler(event, ctx);
      }
    });

    api.logger.info('ClawGuard initialized successfully', {
      hooks: ['message_received', 'before_tool_call'],
      shield: config.shield.enabled,
      scanner: config.scanner.enabled,
      enclave: config.enclave.enabled,
      selfModification: config.selfModification.enabled,
      audit: config.audit.enabled,
    });
  },
};

// Default export for plugin
export default clawguardPlugin;

// Re-export SDK types (so consumers can use the matched interface)
export type { OpenClawPluginApi, PluginLogger } from './sdk-types';

// Re-export config types
export {
  ClawGuardPluginConfig,
  ClawGuardPluginConfigInput,
  ClawGuardPluginConfigSchema,
  DEFAULT_CONFIG,
  resolveConfig,
  applyWorkspaceDetection,
  detectWorkspaceFiles,
  mergeProtectedFiles,
  expandPath,
  BLOCKED_CATEGORIES,
  type BlockedCategory,
} from './config';

// Re-export CLI registration
export { registerCli } from './cli';
