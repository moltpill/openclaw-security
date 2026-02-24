/**
 * File Watch Hook
 *
 * Handles the before_tool_call hook for file-related tools, protecting
 * enclave files and scanning content for secrets.
 *
 * This hook is called from the before_tool_call handler in plugin/index.ts
 * after filtering for file-related tool names.
 *
 * Covered tools: exec, read, write, edit, bash, read_file, write_file
 *
 * BLOCKING SUPPORT:
 *   The OpenClaw SDK before_tool_call hook supports returning
 *   { block: true, blockReason } to prevent the tool from executing.
 *
 *   Hard-block cases (no approval configured):
 *     - Write to a protected enclave file
 *     - File write containing secrets with onDetection='block'
 *
 *   Soft cases (logged + allowed through):
 *     - Write to protected enclave file when requireApproval=true
 *     - Secret detected with onDetection='warn' or 'redact'
 */

import { ClawGuard } from '../../clawguard';
import { ClawGuardPluginConfig } from '../config';
import type { PluginLogger, PluginHookBeforeToolCallResult } from '../sdk-types';

export interface BeforeToolCallEvent {
  toolName: string;
  params: Record<string, unknown>;
}

/**
 * Creates the file-watch handler for enclave protection + secret scanning.
 * Called only for file-related tools (filtered in plugin/index.ts).
 */
export function createFileWatchHook(
  guard: ClawGuard,
  config: ClawGuardPluginConfig,
  logger: PluginLogger,
) {
  return async (
    event: BeforeToolCallEvent,
    _ctx?: unknown,
  ): Promise<PluginHookBeforeToolCallResult | void> => {
    const { toolName, params } = event;

    // Resolve the file path from params
    const filePath = resolveFilePath(toolName, params);
    const content = (params['content'] ?? params['new_string'] ?? params['newText']) as
      | string
      | undefined;
    const isWrite = isWriteOperation(toolName, params);

    // ── Enclave protection ────────────────────────────────────────────────
    if (filePath && isWrite && config.enclave.enabled) {
      if (guard.isProtectedFile(filePath)) {
        if (config.enclave.requireApproval) {
          // Soft: log and let through — approval flow handles the gate
          logger.warn(
            `ClawGuard: Write to protected enclave file detected — ${filePath}`,
            { toolName, filePath, requiresApproval: true },
          );
          return;
        } else {
          // Hard block: deny the write entirely
          logger.error(
            `ClawGuard: Write to protected enclave file blocked — ${filePath}`,
            { toolName, filePath, blocked: true },
          );
          return {
            block: true,
            blockReason: `ClawGuard: Write to protected enclave file: ${filePath}`,
          };
        }
      }
    }

    // ── Secret scanner ────────────────────────────────────────────────────
    if (content && isWrite && config.scanner.enabled) {
      const scanResult = guard.scanContent(content, 'write');

      if (!scanResult.safe) {
        switch (config.scanner.onDetection) {
          case 'block':
            logger.error(
              `ClawGuard: File write contains secrets — blocked (${filePath ?? toolName})`,
              { toolName, filePath },
            );
            return {
              block: true,
              blockReason: `ClawGuard: File write contains secrets: ${filePath ?? toolName}`,
            };

          case 'warn':
            logger.warn(
              `ClawGuard: File write contains potential secrets — ${filePath ?? toolName}`,
              { toolName, filePath },
            );
            return;

          case 'redact':
            // Cannot modify content in the hook without returning modified params.
            // Log the violation and allow through — content is logged for audit.
            logger.warn(
              `ClawGuard: File write would have been redacted — ${filePath ?? toolName}`,
              { toolName, filePath },
            );
            // TODO: return { params: { ...params, content: scanResult.redactedContent } }
            // once the plugin config surfaces redactedContent reliably.
            return;

          default:
            break;
        }
      }
    }

    logger.debug?.('ClawGuard: File tool checked, no issues', { toolName, filePath });
  };
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function resolveFilePath(
  toolName: string,
  params: Record<string, unknown>,
): string | undefined {
  return (
    params['path'] ??
    params['file_path'] ??
    params['filePath'] ??
    (toolName === 'exec' || toolName === 'bash' ? params['command'] : undefined)
  ) as string | undefined;
}

function isWriteOperation(toolName: string, params: Record<string, unknown>): boolean {
  if (['write', 'write_file'].includes(toolName)) return true;
  if (['edit'].includes(toolName)) return true;
  if (['exec', 'bash'].includes(toolName)) {
    // Heuristic: contains write-like shell commands
    const cmd = (params['command'] ?? params['cmd'] ?? '') as string;
    return /\b(echo|tee|cp|mv|rm|cat >|>|>>|\bwrite\b|\binstall\b)\b/i.test(cmd);
  }
  return false;
}
