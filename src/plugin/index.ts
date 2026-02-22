/**
 * ClawGuard OpenClaw Plugin
 * 
 * Security layer for OpenClaw agents - injection detection,
 * secret scanning, enclave protection, and audit logging.
 */

import { ClawGuard, createClawGuard } from '../clawguard';
import { 
  ClawGuardPluginConfigSchema, 
  ClawGuardPluginConfig,
  ClawGuardPluginConfigInput,
  DEFAULT_CONFIG,
  resolveConfig,
} from './config';
import { createMessageShieldHook } from './hooks/message-shield';
import { createToolGuardHook } from './hooks/tool-guard';
import { createFileWatchHook } from './hooks/file-watch';

/**
 * OpenClaw Plugin API interface
 * 
 * Note: This is a placeholder interface based on expected API.
 * Will be updated once OpenClaw's plugin SDK is finalized.
 */
export interface OpenClawPluginApi {
  /** Register a hook handler */
  registerHook(hookName: string, handler: (ctx: unknown) => Promise<unknown>): void;
  
  /** Request user approval for an action */
  requestApproval(request: {
    type: string;
    message: string;
    details?: Record<string, unknown>;
  }): Promise<{ approved: boolean; reason?: string }>;
  
  /** Log a message */
  log(level: 'debug' | 'info' | 'warn' | 'error', message: string, data?: unknown): void;
  
  /** Get plugin configuration */
  getConfig<T>(): T;
  
  /** Get workspace path */
  getWorkspacePath(): string;
}

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
  description: 'Security layer for OpenClaw agents - injection detection, secret scanning, enclave protection, and audit logging',
  
  /** Plugin version */
  version: '0.1.0',
  
  /** Configuration schema for validation */
  configSchema: ClawGuardPluginConfigSchema,
  
  /** Hooks this plugin uses */
  hooks: ['message:before', 'tool:before', 'file:before'] as const,
  
  /**
   * Register the plugin with OpenClaw
   */
  async register(api: OpenClawPluginApi): Promise<PluginRegistrationResult> {
    // Get plugin configuration (with defaults)
    const userConfig = api.getConfig<ClawGuardPluginConfigInput>() || {};
    const config = resolveConfig(userConfig);
    
    api.log('info', 'ClawGuard initializing...', { config });
    
    // Create and initialize ClawGuard instance
    const guard = await createClawGuard({
      enclavePath: api.getWorkspacePath(),
    });
    
    // Register message:before hook
    api.registerHook('message:before', async (ctx) => {
      const handler = createMessageShieldHook(guard, config);
      const result = await handler(ctx as Parameters<typeof handler>[0]);
      
      if (!result.continue && result.error) {
        throw result.error;
      }
      
      if (result.warning) {
        api.log('warn', result.warning);
      }
      
      return result.context || ctx;
    });
    
    // Register tool:before hook
    api.registerHook('tool:before', async (ctx) => {
      const handler = createToolGuardHook(guard, config);
      const result = await handler(ctx as Parameters<typeof handler>[0]);
      
      if (!result.continue) {
        if (result.requestApproval) {
          const approval = await api.requestApproval({
            type: result.requestApproval.type,
            message: result.requestApproval.reason,
            details: {
              tool: result.requestApproval.tool,
              action: result.requestApproval.action,
              command: result.requestApproval.command,
              category: result.requestApproval.category,
            },
          });
          
          if (!approval.approved) {
            throw new Error(`Action denied: ${approval.reason || 'User rejected'}`);
          }
          
          // Approved - continue with original context
          return ctx;
        }
        
        if (result.error) {
          throw result.error;
        }
      }
      
      return result.context || ctx;
    });
    
    // Register file:before hook
    api.registerHook('file:before', async (ctx) => {
      const handler = createFileWatchHook(guard, config);
      const result = await handler(ctx as Parameters<typeof handler>[0]);
      
      if (!result.continue) {
        if (result.requestApproval) {
          const approval = await api.requestApproval({
            type: result.requestApproval.type,
            message: result.requestApproval.reason,
            details: {
              path: result.requestApproval.path,
            },
          });
          
          if (!approval.approved) {
            throw new Error(`File access denied: ${approval.reason || 'User rejected'}`);
          }
          
          // Approved - continue with original context
          return ctx;
        }
        
        if (result.error) {
          throw result.error;
        }
      }
      
      if (result.warning) {
        api.log('warn', result.warning);
      }
      
      return result.context || ctx;
    });
    
    api.log('info', 'ClawGuard initialized successfully', {
      hooks: clawguardPlugin.hooks,
      shield: config.shield.enabled,
      scanner: config.scanner.enabled,
      enclave: config.enclave.enabled,
      selfModification: config.selfModification.enabled,
      audit: config.audit.enabled,
    });
    
    return { success: true, guard };
  },
};

// Default export for plugin
export default clawguardPlugin;

// Re-export config types
export { 
  ClawGuardPluginConfig, 
  ClawGuardPluginConfigInput,
  ClawGuardPluginConfigSchema, 
  DEFAULT_CONFIG, 
  resolveConfig,
  BLOCKED_CATEGORIES,
  type BlockedCategory,
} from './config';

// Re-export hook types
export type { MessageHookContext, MessageHookResult } from './hooks/message-shield';
export type { ToolHookContext, ToolHookResult, ApprovalRequest } from './hooks/tool-guard';
export type { FileHookContext, FileHookResult, EnclaveApprovalRequest } from './hooks/file-watch';
