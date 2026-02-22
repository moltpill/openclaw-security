/**
 * Message Shield Hook
 * 
 * Implements the message:before hook for scanning inbound messages
 * for injection attempts and other threats.
 */

import { ClawGuard } from '../../clawguard';
import { ClawGuardPluginConfig } from '../config';
import { ThreatLevel } from '../../types';

/**
 * Context provided by OpenClaw for message:before hook
 */
export interface MessageHookContext {
  message: {
    content: string;
    senderId?: string;
    isExternal?: boolean;
  };
  channel: {
    id: string;
    type?: string;
  };
  session?: {
    id: string;
  };
}

/**
 * Result returned from the hook
 */
export interface MessageHookResult {
  /** Whether to continue processing the message */
  continue: boolean;
  /** Modified context (if any) */
  context?: MessageHookContext;
  /** Error to throw if blocking */
  error?: Error;
  /** Warning message to log */
  warning?: string;
  /** Metadata to attach */
  metadata?: Record<string, unknown>;
}

/**
 * Creates the message:before hook handler
 */
export function createMessageShieldHook(
  guard: ClawGuard,
  config: ClawGuardPluginConfig
) {
  return async (ctx: MessageHookContext): Promise<MessageHookResult> => {
    // Skip if shield is disabled
    if (!config.shield.enabled) {
      return { continue: true };
    }

    // Scan the message
    const result = guard.scanMessage(ctx.message.content, {
      channel: ctx.channel.id,
      senderId: ctx.message.senderId,
      isExternal: ctx.message.isExternal ?? true,
      sessionId: ctx.session?.id,
    });

    // Handle based on result
    if (result.action === 'block') {
      return {
        continue: false,
        error: new Error(
          `Message blocked by ClawGuard: ${result.threats.map(t => t.pattern).join(', ')}`
        ),
        metadata: {
          clawguard: {
            blocked: true,
            threatLevel: result.threatLevel,
            threats: result.threats,
          },
        },
      };
    }

    if (result.action === 'warn') {
      // Allow but warn
      return {
        continue: true,
        warning: `ClawGuard detected potential threats: ${result.threats.map(t => t.pattern).join(', ')}`,
        metadata: {
          clawguard: {
            warned: true,
            threatLevel: result.threatLevel,
            threats: result.threats,
          },
        },
      };
    }

    // Check if we should use redacted content
    if (result.redactedContent && config.scanner.onDetection === 'redact') {
      return {
        continue: true,
        context: {
          ...ctx,
          message: {
            ...ctx.message,
            content: result.redactedContent,
          },
        },
        metadata: {
          clawguard: {
            redacted: true,
            originalLength: ctx.message.content.length,
          },
        },
      };
    }

    // All clear
    return {
      continue: true,
      metadata: {
        clawguard: {
          scanned: true,
          threatLevel: result.threatLevel,
          safe: result.safe,
        },
      },
    };
  };
}
