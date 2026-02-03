/**
 * Approval Manager
 * 
 * Orchestrates the human-in-the-loop approval workflow between
 * the SecureEnclave and ApprovalChannel.
 */

import { SecureEnclave } from '../enclave/secure-enclave';
import { 
  ApprovalChannel, 
  ApprovalChannelConfig, 
  ApprovalResponse, 
  PendingApproval,
  MessageCommand 
} from './approval-channel';
import { EnclaveChangeRequest, AuditEvent, AuditEventType } from '../types';

export interface ApprovalManagerConfig {
  /** Enclave instance to manage approvals for */
  enclave: SecureEnclave;
  
  /** Channel configuration */
  channel: ApprovalChannelConfig;
  
  /** Callback when a message needs to be sent */
  onSendMessage?: (command: MessageCommand) => Promise<string | void>;
  
  /** Callback for audit events */
  onAuditEvent?: (event: AuditEvent) => void;
  
  /** Auto-expire check interval in ms (default: 5 minutes) */
  expiryCheckIntervalMs?: number;
}

export interface RequestApprovalResult {
  success: boolean;
  requestId?: string;
  messageCommand?: MessageCommand;
  error?: string;
}

export interface ProcessResponseResult {
  matched: boolean;
  requestId?: string;
  action?: 'approved' | 'denied' | 'expired' | 'not_found';
  confirmationCommand?: MessageCommand;
  error?: string;
}

export class ApprovalManager {
  private enclave: SecureEnclave;
  private channel: ApprovalChannel;
  private onSendMessage?: (command: MessageCommand) => Promise<string | void>;
  private onAuditEvent?: (event: AuditEvent) => void;
  private expiryTimer?: ReturnType<typeof setInterval>;
  private expiryCheckIntervalMs: number;

  constructor(config: ApprovalManagerConfig) {
    this.enclave = config.enclave;
    this.channel = new ApprovalChannel(config.channel);
    this.onSendMessage = config.onSendMessage;
    this.onAuditEvent = config.onAuditEvent;
    this.expiryCheckIntervalMs = config.expiryCheckIntervalMs ?? 5 * 60 * 1000;
  }

  /**
   * Initialize the approval manager
   */
  async initialize(): Promise<void> {
    await this.channel.initialize();
    this.startExpiryChecker();
  }

  /**
   * Stop the approval manager
   */
  stop(): void {
    if (this.expiryTimer) {
      clearInterval(this.expiryTimer);
      this.expiryTimer = undefined;
    }
  }

  /**
   * Request approval for an enclave change
   * 
   * This is the main entry point for agents requesting changes.
   */
  async requestApproval(
    file: string,
    newContent: string,
    reason: string,
    timeoutMs?: number
  ): Promise<RequestApprovalResult> {
    // Create the enclave change request
    const enclaveResult = await this.enclave.requestChange(file, newContent, reason);

    if (!enclaveResult.success) {
      return {
        success: false,
        error: enclaveResult.error
      };
    }

    const requestId = enclaveResult.requestId!;
    const request = this.enclave.getRequestStatus(requestId);

    if (!request) {
      return {
        success: false,
        error: 'Failed to retrieve request after creation'
      };
    }

    // Create and send approval message
    const { pending, command } = this.channel.createApprovalMessage(request, timeoutMs);

    // Register the pending approval
    let messageId: string | undefined;
    if (this.onSendMessage) {
      const result = await this.onSendMessage(command);
      messageId = typeof result === 'string' ? result : undefined;
    }

    await this.channel.registerPending(pending, messageId);

    // Audit log
    this.audit(AuditEventType.ENCLAVE_REQUEST, {
      requestId,
      file,
      reason,
      channel: command.channel,
      target: command.target
    });

    return {
      success: true,
      requestId,
      messageCommand: command
    };
  }

  /**
   * Process an incoming message that might be an approval response
   */
  async processIncomingMessage(
    messageText: string,
    senderId?: string
  ): Promise<ProcessResponseResult> {
    // Try to parse as approval response
    const response = this.channel.parseResponse(messageText, senderId);

    if (!response) {
      return { matched: false };
    }

    // Match to pending approval
    const pending = this.channel.matchResponse(response);

    if (!pending) {
      // Could be expired or not found
      const allPending = this.channel.getPending(response.requestId);
      if (allPending) {
        return {
          matched: true,
          requestId: response.requestId,
          action: 'expired',
          error: 'Request has expired'
        };
      }
      return {
        matched: true,
        requestId: response.requestId,
        action: 'not_found',
        error: 'Request not found'
      };
    }

    // Process the approval/denial
    let confirmationCommand: MessageCommand;
    let action: 'approved' | 'denied';

    if (response.approved) {
      const result = await this.enclave.approveRequest(
        response.requestId,
        response.respondedBy ?? 'human'
      );

      if (!result.success) {
        return {
          matched: true,
          requestId: response.requestId,
          error: result.error
        };
      }

      confirmationCommand = this.channel.createApprovedMessage(pending);
      action = 'approved';
    } else {
      const result = await this.enclave.denyRequest(
        response.requestId,
        response.respondedBy ?? 'human'
      );

      if (!result.success) {
        return {
          matched: true,
          requestId: response.requestId,
          error: result.error
        };
      }

      confirmationCommand = this.channel.createDeniedMessage(pending);
      action = 'denied';
    }

    // Clean up
    await this.channel.resolveRequest(response.requestId);

    // Send confirmation
    if (this.onSendMessage) {
      await this.onSendMessage(confirmationCommand);
    }

    // Audit log
    this.audit(AuditEventType.ENCLAVE_DECISION, {
      requestId: response.requestId,
      file: pending.file,
      action,
      respondedBy: response.respondedBy,
      rawResponse: response.rawResponse
    });

    return {
      matched: true,
      requestId: response.requestId,
      action,
      confirmationCommand
    };
  }

  /**
   * Check request status
   */
  getRequestStatus(requestId: string): {
    enclave?: EnclaveChangeRequest;
    pending?: PendingApproval;
  } {
    return {
      enclave: this.enclave.getRequestStatus(requestId),
      pending: this.channel.getPending(requestId)
    };
  }

  /**
   * Get all pending approvals
   */
  getAllPendingApprovals(): PendingApproval[] {
    return this.channel.getAllPending();
  }

  /**
   * Manually expire a request
   */
  async expireRequest(requestId: string): Promise<boolean> {
    const pending = this.channel.getPending(requestId);
    
    if (!pending) {
      return false;
    }

    // Update enclave status
    const expired = await this.enclave.expirePendingRequests();
    
    // Clean up channel tracking
    await this.channel.resolveRequest(requestId);

    // Send expiry notification
    if (this.onSendMessage) {
      const command = this.channel.createExpiredMessage(pending);
      await this.onSendMessage(command);
    }

    // Audit
    this.audit(AuditEventType.ENCLAVE_DECISION, {
      requestId,
      file: pending.file,
      action: 'expired',
      reason: 'manual'
    });

    return true;
  }

  /**
   * Check for expired requests
   */
  async checkExpiredRequests(): Promise<PendingApproval[]> {
    // Check enclave for expired requests
    await this.enclave.expirePendingRequests();

    // Check channel for expired pending approvals
    const expired = await this.channel.checkExpired();

    // Send notifications and audit for each
    for (const pending of expired) {
      if (this.onSendMessage) {
        const command = this.channel.createExpiredMessage(pending);
        await this.onSendMessage(command);
      }

      this.audit(AuditEventType.ENCLAVE_DECISION, {
        requestId: pending.requestId,
        file: pending.file,
        action: 'expired',
        reason: 'timeout'
      });
    }

    return expired;
  }

  /**
   * Resend an approval request
   */
  async resendApprovalRequest(requestId: string): Promise<MessageCommand | null> {
    const status = this.getRequestStatus(requestId);

    if (!status.enclave || status.enclave.status !== 'pending') {
      return null;
    }

    const { command } = this.channel.createApprovalMessage(status.enclave);

    if (this.onSendMessage) {
      await this.onSendMessage(command);
    }

    return command;
  }

  /**
   * Get the underlying channel for direct access
   */
  getChannel(): ApprovalChannel {
    return this.channel;
  }

  /**
   * Get the underlying enclave for direct access
   */
  getEnclave(): SecureEnclave {
    return this.enclave;
  }

  // ============ Private Methods ============

  private startExpiryChecker(): void {
    this.expiryTimer = setInterval(async () => {
      try {
        await this.checkExpiredRequests();
      } catch (error) {
        // Log but don't throw - don't want timer to stop
        console.error('Error checking expired requests:', error);
      }
    }, this.expiryCheckIntervalMs);
  }

  private audit(eventType: AuditEventType, data: Record<string, unknown>): void {
    if (this.onAuditEvent) {
      this.onAuditEvent({
        timestamp: new Date(),
        eventType,
        data
      });
    }
  }
}
