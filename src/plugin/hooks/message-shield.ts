/**
 * Message Shield Hook
 *
 * Handles the message_received hook for scanning inbound messages
 * for injection attempts and other threats.
 *
 * NOTE: message_received is read-only in the current OpenClaw SDK.
 * Threats are logged and audited but cannot block the message mid-flight.
 * Blocking support requires future SDK approval API.
 */

import { ClawGuard } from '../../clawguard';
import { ClawGuardPluginConfig } from '../config';
import type { PluginLogger } from '../sdk-types';

/**
 * Context shape for the message_received hook (matches real OpenClaw SDK).
 */
export interface MessageReceivedEvent {
  from: string;
  content: string;
  timestamp?: number;
  metadata?: Record<string, unknown>;
}

/**
 * Creates the message_received hook handler.
 */
export function createMessageShieldHook(
  guard: ClawGuard,
  config: ClawGuardPluginConfig,
  logger: PluginLogger,
) {
  return async (event: MessageReceivedEvent, _ctx?: unknown): Promise<void> => {
    if (!config.shield.enabled) return;

    const result = guard.scanMessage(event.content, {
      channel: (event.metadata?.['channelId'] as string | undefined) ?? 'unknown',
      senderId: event.from,
      isExternal: true,
      sessionId: (event.metadata?.['sessionKey'] as string | undefined),
    });

    if (result.action === 'block') {
      // Read-only: cannot block, but log at error level and audit
      logger.error(
        `ClawGuard: Injection detected in message from ${event.from} — ` +
          result.threats.map((t) => t.pattern).join(', '),
        { threatLevel: result.threatLevel, threats: result.threats },
      );
      return;
    }

    if (result.action === 'warn') {
      logger.warn(
        `ClawGuard: Potential threat in message from ${event.from} — ` +
          result.threats.map((t) => t.pattern).join(', '),
        { threatLevel: result.threatLevel, threats: result.threats },
      );
      return;
    }

    // All clear — debug log only
    logger.debug?.('ClawGuard: Message scanned, no threats detected', {
      from: event.from,
      threatLevel: result.threatLevel,
    });
  };
}
