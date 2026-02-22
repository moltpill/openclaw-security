/**
 * File Watch Hook
 * 
 * Implements the file:before hook for protecting enclave files
 * and scanning file content for secrets.
 */

import { ClawGuard } from '../../clawguard';
import { ClawGuardPluginConfig } from '../config';

/**
 * Context provided by OpenClaw for file:before hook
 */
export interface FileHookContext {
  operation: 'read' | 'write' | 'delete';
  path: string;
  content?: string;
  session?: {
    id: string;
  };
}

/**
 * Enclave approval request
 */
export interface EnclaveApprovalRequest {
  type: 'enclave-write';
  path: string;
  content: string;
  reason: string;
}

/**
 * Result returned from the hook
 */
export interface FileHookResult {
  /** Whether to continue with the file operation */
  continue: boolean;
  /** Modified context (if any) */
  context?: FileHookContext;
  /** Error to throw if blocking */
  error?: Error;
  /** Request approval from user */
  requestApproval?: EnclaveApprovalRequest;
  /** Warning message to log */
  warning?: string;
  /** Metadata to attach */
  metadata?: Record<string, unknown>;
}

/**
 * Creates the file:before hook handler
 */
export function createFileWatchHook(
  guard: ClawGuard,
  config: ClawGuardPluginConfig
) {
  return async (ctx: FileHookContext): Promise<FileHookResult> => {
    const sessionId = ctx.session?.id;

    // Check enclave protection for writes and deletes
    if (ctx.operation === 'write' || ctx.operation === 'delete') {
      if (config.enclave.enabled && guard.isProtectedFile(ctx.path)) {
        if (config.enclave.requireApproval) {
          return {
            continue: false,
            requestApproval: {
              type: 'enclave-write',
              path: ctx.path,
              content: ctx.content || '',
              reason: `Modification to protected file: ${ctx.path}`,
            },
            metadata: {
              clawguard: {
                enclave: true,
                protected: true,
                requiresApproval: true,
              },
            },
          };
        }

        // Hard block without approval option
        return {
          continue: false,
          error: new Error(`ClawGuard: Cannot modify protected file: ${ctx.path}`),
          metadata: {
            clawguard: {
              enclave: true,
              protected: true,
              blocked: true,
            },
          },
        };
      }
    }

    // Scan content for secrets on write
    if (ctx.operation === 'write' && ctx.content && config.scanner.enabled) {
      const scanResult = guard.scanContent(ctx.content, 'write');

      if (!scanResult.safe) {
        switch (config.scanner.onDetection) {
          case 'block':
            return {
              continue: false,
              error: new Error('ClawGuard: File write blocked - contains secrets'),
              metadata: {
                clawguard: {
                  secretScan: true,
                  blocked: true,
                },
              },
            };

          case 'redact':
            if (scanResult.redactedContent) {
              return {
                continue: true,
                context: {
                  ...ctx,
                  content: scanResult.redactedContent,
                },
                warning: 'ClawGuard: Secrets were redacted from file content',
                metadata: {
                  clawguard: {
                    secretScan: true,
                    redacted: true,
                  },
                },
              };
            }
            break;

          case 'warn':
            return {
              continue: true,
              warning: 'ClawGuard: File write contains potential secrets',
              metadata: {
                clawguard: {
                  secretScan: true,
                  warned: true,
                },
              },
            };

          case 'allow':
          default:
            // Fall through to allow
            break;
        }
      }
    }

    // Scan content for secrets on read (for logging purposes)
    if (ctx.operation === 'read' && config.scanner.enabled) {
      // Just attach metadata that scanning will happen on the content
      return {
        continue: true,
        metadata: {
          clawguard: {
            willScan: true,
          },
        },
      };
    }

    // All clear
    return {
      continue: true,
      metadata: {
        clawguard: {
          checked: true,
          operation: ctx.operation,
        },
      },
    };
  };
}
