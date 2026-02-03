/**
 * Approval Channel
 * 
 * Handles human-in-the-loop approval workflow via messaging platforms
 * (WhatsApp, Telegram, etc.) using OpenClaw's message tool.
 */

import * as fs from 'fs';
import * as path from 'path';
import { EnclaveChangeRequest } from '../types';

export interface ApprovalChannelConfig {
  /** Messaging platform to use (whatsapp, telegram) */
  channel: 'whatsapp' | 'telegram' | string;
  
  /** Target contact/chat ID to send approval requests to */
  target: string;
  
  /** Default timeout in ms (default: 1 hour) */
  defaultTimeoutMs?: number;
  
  /** Path to persist pending approvals */
  persistPath?: string;
  
  /** Max lines of diff to include in message */
  maxDiffLines?: number;
  
  /** Custom message templates */
  templates?: Partial<ApprovalTemplates>;
}

export interface ApprovalTemplates {
  requestHeader: string;
  requestBody: string;
  requestFooter: string;
  approved: string;
  denied: string;
  expired: string;
}

export interface PendingApproval {
  requestId: string;
  messageId?: string;
  file: string;
  reason: string;
  diff: string;
  requestedBy: string;
  requestedAt: Date;
  expiresAt: Date;
  channel: string;
  target: string;
}

export interface ApprovalResponse {
  approved: boolean;
  requestId: string;
  respondedBy?: string;
  respondedAt: Date;
  rawResponse: string;
}

export interface MessageCommand {
  action: 'send';
  channel: string;
  target: string;
  message: string;
}

const DEFAULT_TEMPLATES: ApprovalTemplates = {
  requestHeader: '🔒 *APPROVAL NEEDED*',
  requestBody: `
📄 *File:* {file}
👤 *Requested by:* {requestedBy}
⏰ *Expires:* {expiresIn}
📝 *Reason:* {reason}

{diffSection}`,
  requestFooter: `
Reply with:
✅ *YES* or *APPROVE* — Accept this change
❌ *NO* or *DENY* — Reject this change

_Request ID: {requestId}_`,
  approved: '✅ Change to {file} has been *approved*.',
  denied: '❌ Change to {file} has been *denied*.',
  expired: '⏰ Approval request for {file} has *expired*.'
};

export class ApprovalChannel {
  private config: Required<ApprovalChannelConfig>;
  private pendingApprovals: Map<string, PendingApproval>;
  private templates: ApprovalTemplates;

  constructor(config: ApprovalChannelConfig) {
    this.config = {
      channel: config.channel,
      target: config.target,
      defaultTimeoutMs: config.defaultTimeoutMs ?? 60 * 60 * 1000, // 1 hour
      persistPath: config.persistPath ?? '',
      maxDiffLines: config.maxDiffLines ?? 15,
      templates: config.templates ?? {}
    };

    this.templates = { ...DEFAULT_TEMPLATES, ...config.templates };
    this.pendingApprovals = new Map();
  }

  /**
   * Initialize the approval channel (load persisted state)
   */
  async initialize(): Promise<void> {
    if (this.config.persistPath) {
      await this.loadPendingApprovals();
    }
  }

  /**
   * Create an approval request message for a change request
   */
  createApprovalMessage(request: EnclaveChangeRequest, timeoutMs?: number): {
    message: string;
    pending: PendingApproval;
    command: MessageCommand;
  } {
    const timeout = timeoutMs ?? this.config.defaultTimeoutMs;
    const expiresAt = new Date(Date.now() + timeout);

    const pending: PendingApproval = {
      requestId: request.id,
      file: request.file,
      reason: request.reason,
      diff: request.diff,
      requestedBy: request.requestedBy,
      requestedAt: request.requestedAt,
      expiresAt,
      channel: this.config.channel,
      target: this.config.target
    };

    const message = this.formatApprovalMessage(pending);

    const command: MessageCommand = {
      action: 'send',
      channel: this.config.channel,
      target: this.config.target,
      message
    };

    return { message, pending, command };
  }

  /**
   * Register a pending approval (call after message is sent)
   */
  async registerPending(pending: PendingApproval, messageId?: string): Promise<void> {
    pending.messageId = messageId;
    this.pendingApprovals.set(pending.requestId, pending);
    await this.persistPendingApprovals();
  }

  /**
   * Get a pending approval by request ID
   */
  getPending(requestId: string): PendingApproval | undefined {
    return this.pendingApprovals.get(requestId);
  }

  /**
   * Get all pending approvals
   */
  getAllPending(): PendingApproval[] {
    return Array.from(this.pendingApprovals.values());
  }

  /**
   * Parse an incoming message to check if it's an approval response
   */
  parseResponse(
    messageText: string,
    senderId?: string
  ): ApprovalResponse | null {
    const text = messageText.trim().toUpperCase();
    
    // Check for explicit approval/denial patterns
    const approvalPatterns = ['YES', 'APPROVE', 'APPROVED', 'OK', 'ACCEPT', '✅', 'Y'];
    const denialPatterns = ['NO', 'DENY', 'DENIED', 'REJECT', 'REJECTED', '❌', 'N'];

    let approved: boolean | null = null;

    // Check if message contains approval
    for (const pattern of approvalPatterns) {
      if (text === pattern || text.startsWith(pattern + ' ') || text.startsWith(pattern + '\n')) {
        approved = true;
        break;
      }
    }

    // Check if message contains denial
    if (approved === null) {
      for (const pattern of denialPatterns) {
        if (text === pattern || text.startsWith(pattern + ' ') || text.startsWith(pattern + '\n')) {
          approved = false;
          break;
        }
      }
    }

    if (approved === null) {
      return null;
    }

    // Try to extract request ID from message
    const requestIdMatch = messageText.match(/req_[a-z0-9_]+/i);
    let requestId: string | undefined;

    if (requestIdMatch) {
      requestId = requestIdMatch[0];
    } else {
      // If no request ID, assume it's for the most recent pending request
      const pendingList = this.getAllPending()
        .filter(p => p.expiresAt > new Date())
        .sort((a, b) => b.requestedAt.getTime() - a.requestedAt.getTime());
      
      if (pendingList.length === 1) {
        requestId = pendingList[0].requestId;
      } else if (pendingList.length > 1) {
        // Ambiguous - take most recent but this is a limitation
        requestId = pendingList[0].requestId;
      }
    }

    if (!requestId) {
      return null;
    }

    return {
      approved,
      requestId,
      respondedBy: senderId,
      respondedAt: new Date(),
      rawResponse: messageText
    };
  }

  /**
   * Match a response to a pending approval
   */
  matchResponse(response: ApprovalResponse): PendingApproval | null {
    const pending = this.pendingApprovals.get(response.requestId);
    
    if (!pending) {
      return null;
    }

    // Check if expired
    if (pending.expiresAt < new Date()) {
      return null;
    }

    return pending;
  }

  /**
   * Mark a request as resolved (approved or denied)
   */
  async resolveRequest(requestId: string): Promise<void> {
    this.pendingApprovals.delete(requestId);
    await this.persistPendingApprovals();
  }

  /**
   * Check for and return expired approvals
   */
  async checkExpired(): Promise<PendingApproval[]> {
    const now = new Date();
    const expired: PendingApproval[] = [];

    for (const [id, pending] of this.pendingApprovals) {
      if (pending.expiresAt < now) {
        expired.push(pending);
        this.pendingApprovals.delete(id);
      }
    }

    if (expired.length > 0) {
      await this.persistPendingApprovals();
    }

    return expired;
  }

  /**
   * Create a confirmation message for approved change
   */
  createApprovedMessage(pending: PendingApproval): MessageCommand {
    const message = this.templates.approved.replace('{file}', pending.file);
    return {
      action: 'send',
      channel: pending.channel,
      target: pending.target,
      message
    };
  }

  /**
   * Create a confirmation message for denied change
   */
  createDeniedMessage(pending: PendingApproval): MessageCommand {
    const message = this.templates.denied.replace('{file}', pending.file);
    return {
      action: 'send',
      channel: pending.channel,
      target: pending.target,
      message
    };
  }

  /**
   * Create a notification for expired request
   */
  createExpiredMessage(pending: PendingApproval): MessageCommand {
    const message = this.templates.expired.replace('{file}', pending.file);
    return {
      action: 'send',
      channel: pending.channel,
      target: pending.target,
      message
    };
  }

  /**
   * Format the full approval request message
   */
  private formatApprovalMessage(pending: PendingApproval): string {
    const expiresIn = this.formatTimeRemaining(pending.expiresAt);
    const diffSection = this.formatDiffSection(pending.diff);

    let body = this.templates.requestBody
      .replace('{file}', pending.file)
      .replace('{requestedBy}', pending.requestedBy)
      .replace('{expiresIn}', expiresIn)
      .replace('{reason}', pending.reason)
      .replace('{diffSection}', diffSection);

    const footer = this.templates.requestFooter
      .replace('{requestId}', pending.requestId);

    return [
      this.templates.requestHeader,
      body.trim(),
      footer.trim()
    ].join('\n\n');
  }

  /**
   * Format diff for display in message
   */
  private formatDiffSection(diff: string): string {
    const lines = diff.split('\n');
    
    if (lines.length <= this.config.maxDiffLines) {
      return '```\n' + diff + '\n```';
    }

    // Truncate and add indicator
    const truncated = lines.slice(0, this.config.maxDiffLines).join('\n');
    const remaining = lines.length - this.config.maxDiffLines;
    
    return `\`\`\`\n${truncated}\n... (${remaining} more lines)\n\`\`\``;
  }

  /**
   * Format time remaining in human-readable format
   */
  private formatTimeRemaining(expiresAt: Date): string {
    const ms = expiresAt.getTime() - Date.now();
    
    if (ms < 0) return 'expired';
    
    const minutes = Math.floor(ms / 60000);
    const hours = Math.floor(minutes / 60);
    
    if (hours > 0) {
      const remainingMinutes = minutes % 60;
      if (remainingMinutes > 0) {
        return `${hours}h ${remainingMinutes}m`;
      }
      return `${hours}h`;
    }
    
    return `${minutes}m`;
  }

  /**
   * Persist pending approvals to disk
   */
  private async persistPendingApprovals(): Promise<void> {
    if (!this.config.persistPath) return;

    const data = Array.from(this.pendingApprovals.entries()).map(([id, pending]) => ({
      ...pending,
      requestedAt: pending.requestedAt.toISOString(),
      expiresAt: pending.expiresAt.toISOString()
    }));

    await fs.promises.mkdir(path.dirname(this.config.persistPath), { recursive: true });
    await fs.promises.writeFile(
      this.config.persistPath,
      JSON.stringify(data, null, 2)
    );
  }

  /**
   * Load pending approvals from disk
   */
  private async loadPendingApprovals(): Promise<void> {
    if (!this.config.persistPath) return;

    try {
      const content = await fs.promises.readFile(this.config.persistPath, 'utf-8');
      const data = JSON.parse(content);

      for (const item of data) {
        const pending: PendingApproval = {
          ...item,
          requestedAt: new Date(item.requestedAt),
          expiresAt: new Date(item.expiresAt)
        };
        this.pendingApprovals.set(pending.requestId, pending);
      }
    } catch {
      // File doesn't exist or is invalid, start fresh
    }
  }

  /**
   * Update configuration
   */
  updateConfig(config: Partial<ApprovalChannelConfig>): void {
    Object.assign(this.config, config);
    if (config.templates) {
      this.templates = { ...this.templates, ...config.templates };
    }
  }
}
