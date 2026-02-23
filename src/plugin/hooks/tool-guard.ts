/**
 * Tool Guard Hook
 *
 * Handles the before_tool_call hook for checking tool invocations
 * against security policies and self-modification guards.
 *
 * BLOCKING SUPPORT:
 *   The OpenClaw SDK processes before_tool_call as a modifying hook.
 *   Returning { block: true, blockReason: '...' } prevents the tool
 *   from executing. ClawGuard uses this for hard-block categories.
 *
 *   Soft violations (requiresApproval) are logged at warn level and
 *   allowed through — blocking without the approval flow would break
 *   legitimate agent operations that simply need human sign-off.
 */

import { ClawGuard } from '../../clawguard';
import { ClawGuardPluginConfig } from '../config';
import type { PluginLogger, PluginHookBeforeToolCallResult } from '../sdk-types';

/**
 * Context shape for the before_tool_call hook (matches real OpenClaw SDK).
 */
export interface BeforeToolCallEvent {
  toolName: string;
  params: Record<string, unknown>;
}

/**
 * Creates the before_tool_call handler for tool policy enforcement.
 *
 * Returns PluginHookBeforeToolCallResult to enable actual blocking via the SDK.
 */
export function createToolGuardHook(
  guard: ClawGuard,
  config: ClawGuardPluginConfig,
  logger: PluginLogger,
) {
  return async (
    event: BeforeToolCallEvent,
    _ctx?: unknown,
  ): Promise<PluginHookBeforeToolCallResult | void> => {
    const { toolName, params } = event;

    // ── Self-modification check for exec/bash tools ──────────────────────
    if ((toolName === 'exec' || toolName === 'bash') && config.selfModification.enabled) {
      const command = (params['command'] ?? params['cmd']) as string | undefined;

      if (command) {
        const selfModCheck = guard.checkSelfModification(command);

        if (selfModCheck.blocked) {
          // Hard-block: log and tell the SDK to block the tool call
          logger.error(
            `ClawGuard: Self-modification blocked — ${selfModCheck.reason}`,
            { toolName, command, category: selfModCheck.category },
          );
          return { block: true, blockReason: `ClawGuard: ${selfModCheck.reason}` };
        }

        if (selfModCheck.requiresApproval) {
          // Soft-block: log warning; cannot block without approval flow
          logger.warn(
            `ClawGuard: Self-modification requires approval — ${selfModCheck.reason}`,
            { toolName, command, category: selfModCheck.category },
          );
          // Allow through — human approval handles the gating
          return;
        }
      }
    }

    // ── Tool policy check ─────────────────────────────────────────────────
    const target = resolveTarget(toolName, params);
    const toolCheck = guard.checkTool(toolName, undefined, target);

    if (!toolCheck.allowed) {
      if (toolCheck.requiresApproval) {
        logger.warn(
          `ClawGuard: Tool invocation requires approval — ${toolCheck.reason}`,
          { toolName, params },
        );
        // Allow through pending approval
        return;
      } else {
        logger.error(
          `ClawGuard: Tool invocation blocked — ${toolCheck.reason}`,
          { toolName, params },
        );
        return { block: true, blockReason: `ClawGuard: ${toolCheck.reason}` };
      }
    }

    logger.debug?.('ClawGuard: Tool check passed', { toolName });
  };
}

/**
 * Extract a meaningful target path/url from tool params.
 */
function resolveTarget(
  toolName: string,
  params: Record<string, unknown>,
): string | undefined {
  switch (toolName) {
    case 'read':
    case 'write':
    case 'edit':
      return (params['path'] ?? params['file_path']) as string | undefined;
    case 'exec':
    case 'bash':
      return (params['command'] ?? params['cmd']) as string | undefined;
    case 'browser':
      return params['targetUrl'] as string | undefined;
    case 'message':
      return (params['target'] ?? params['channel']) as string | undefined;
    default:
      return undefined;
  }
}
