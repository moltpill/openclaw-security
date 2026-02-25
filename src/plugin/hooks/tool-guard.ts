/**
 * Tool Guard Hook
 *
 * Handles the before_tool_call hook for checking tool invocations
 * against security policies, command allowlists, and self-modification guards.
 *
 * EXECUTION ORDER:
 *   1. Allowlist check — if command matches, bypass self-mod guard entirely.
 *      If the match is an `elevate` pattern, auto-inject `elevated: true`.
 *   2. Self-modification guard — hard-block or warn for dangerous commands.
 *   3. Tool policy check — general tool access control.
 *
 * BLOCKING:
 *   Return { block: true, blockReason } → OpenClaw prevents tool execution.
 *   Return { params: { ...params, elevated: true } } → auto-elevate.
 */

import { ClawGuard } from '../../clawguard';
import { ClawGuardPluginConfig } from '../config';
import { CommandAllowlist } from '../../guards/command-allowlist';
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
 */
export function createToolGuardHook(
  guard: ClawGuard,
  config: ClawGuardPluginConfig,
  logger: PluginLogger,
) {
  // Build the allowlist once at hook creation time
  const allowlist = new CommandAllowlist(config.allowlist);

  return async (
    event: BeforeToolCallEvent,
    _ctx?: unknown,
  ): Promise<PluginHookBeforeToolCallResult | void> => {
    const { toolName, params } = event;

    // Only exec/bash commands need allowlist + self-mod checking
    if (toolName === 'exec' || toolName === 'bash') {
      const command = (params['command'] ?? params['cmd']) as string | undefined;

      if (command) {
        // ── 1. Allowlist check ───────────────────────────────────────────
        const allowlistResult = allowlist.check(command);

        if (allowlistResult.allowed) {
          logger.info(
            `ClawGuard: Command allowlisted — ${allowlistResult.matchedPattern}`,
            { toolName, command, autoElevate: allowlistResult.autoElevate },
          );

          if (allowlistResult.autoElevate) {
            // Inject elevated: true into the tool params
            return {
              params: { ...params, elevated: true },
            };
          }

          // Allowed, no elevation needed — skip all further checks
          return;
        }

        // ── 2. Self-modification check ───────────────────────────────────
        if (config.selfModification.enabled) {
          const selfModCheck = guard.checkSelfModification(command);

          if (selfModCheck.blocked) {
            logger.error(
              `ClawGuard: Self-modification blocked — ${selfModCheck.reason}`,
              { toolName, command, category: selfModCheck.category },
            );
            return { block: true, blockReason: `ClawGuard: ${selfModCheck.reason}` };
          }

          if (selfModCheck.requiresApproval) {
            logger.warn(
              `ClawGuard: Self-modification requires approval — ${selfModCheck.reason}`,
              { toolName, command, category: selfModCheck.category },
            );
            return;
          }
        }
      }
    }

    // ── 3. Tool policy check ──────────────────────────────────────────────
    const target = resolveTarget(toolName, params);
    const toolCheck = guard.checkTool(toolName, undefined, target);

    if (!toolCheck.allowed) {
      if (toolCheck.requiresApproval) {
        logger.warn(
          `ClawGuard: Tool invocation requires approval — ${toolCheck.reason}`,
          { toolName, params },
        );
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
