/**
 * Approval Module
 * 
 * Human-in-the-loop approval workflow for protected file changes.
 */

export { ApprovalChannel } from './approval-channel';
export type {
  ApprovalChannelConfig,
  ApprovalTemplates,
  PendingApproval,
  ApprovalResponse,
  MessageCommand
} from './approval-channel';

export { ApprovalManager } from './approval-manager';
export type {
  ApprovalManagerConfig,
  RequestApprovalResult,
  ProcessResponseResult
} from './approval-manager';
