/**
 * Tool Guard Hook
 * 
 * Implements the tool:before hook for checking tool invocations
 * against security policies and self-modification guards.
 */

import { ClawGuard } from '../../clawguard';
import { ClawGuardPluginConfig } from '../config';

/**
 * Context provided by OpenClaw for tool:before hook
 */
export interface ToolHookContext {
  tool: {
    name: string;
    action?: string;
  };
  args: Record<string, unknown>;
  session?: {
    id: string;
  };
}

/**
 * Approval request structure
 */
export interface ApprovalRequest {
  type: 'tool-invocation' | 'self-modification';
  tool: string;
  action?: string;
  args?: Record<string, unknown>;
  reason: string;
  command?: string;
  category?: string;
}

/**
 * Result returned from the hook
 */
export interface ToolHookResult {
  /** Whether to continue with the tool invocation */
  continue: boolean;
  /** Modified context (if any) */
  context?: ToolHookContext;
  /** Error to throw if blocking */
  error?: Error;
  /** Request approval from user */
  requestApproval?: ApprovalRequest;
  /** Metadata to attach */
  metadata?: Record<string, unknown>;
}

/**
 * Creates the tool:before hook handler
 */
export function createToolGuardHook(
  guard: ClawGuard,
  config: ClawGuardPluginConfig
) {
  return async (ctx: ToolHookContext): Promise<ToolHookResult> => {
    const sessionId = ctx.session?.id;

    // Check self-modification for exec commands
    if (ctx.tool.name === 'exec' && config.selfModification.enabled) {
      const command = ctx.args.command as string | undefined;
      
      if (command) {
        const selfModCheck = guard.checkSelfModification(command, sessionId);
        
        if (selfModCheck.blocked) {
          // Check if this category requires approval or is hard-blocked
          if (selfModCheck.requiresApproval && config.selfModification.requireApproval) {
            return {
              continue: false,
              requestApproval: {
                type: 'self-modification',
                tool: 'exec',
                command,
                category: selfModCheck.category,
                reason: selfModCheck.reason,
              },
              metadata: {
                clawguard: {
                  selfModification: true,
                  category: selfModCheck.category,
                  requiresApproval: true,
                },
              },
            };
          }
          
          // Hard block
          return {
            continue: false,
            error: new Error(`ClawGuard blocked self-modification: ${selfModCheck.reason}`),
            metadata: {
              clawguard: {
                selfModification: true,
                category: selfModCheck.category,
                blocked: true,
              },
            },
          };
        }
      }
    }

    // Check tool policy
    const toolCheck = guard.checkTool(
      ctx.tool.name,
      ctx.tool.action,
      getToolTarget(ctx),
      sessionId
    );

    if (!toolCheck.allowed) {
      if (toolCheck.requiresApproval) {
        return {
          continue: false,
          requestApproval: {
            type: 'tool-invocation',
            tool: ctx.tool.name,
            action: ctx.tool.action,
            args: ctx.args,
            reason: toolCheck.reason,
          },
          metadata: {
            clawguard: {
              toolCheck: true,
              requiresApproval: true,
            },
          },
        };
      }

      return {
        continue: false,
        error: new Error(`ClawGuard blocked tool: ${toolCheck.reason}`),
        metadata: {
          clawguard: {
            toolCheck: true,
            blocked: true,
            reason: toolCheck.reason,
          },
        },
      };
    }

    // Tool allowed
    return {
      continue: true,
      metadata: {
        clawguard: {
          toolCheck: true,
          allowed: true,
        },
      },
    };
  };
}

/**
 * Extract target from tool args based on tool type
 */
function getToolTarget(ctx: ToolHookContext): string | undefined {
  const { name, action } = ctx.tool;
  const args = ctx.args;

  switch (name) {
    case 'read':
    case 'write':
    case 'edit':
      return (args.path || args.file_path) as string | undefined;
    
    case 'exec':
      return args.command as string | undefined;
    
    case 'browser':
      return args.targetUrl as string | undefined;
    
    case 'message':
      return (args.target || args.channel) as string | undefined;
    
    default:
      return undefined;
  }
}
