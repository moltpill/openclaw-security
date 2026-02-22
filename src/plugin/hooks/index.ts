/**
 * Plugin Hooks Index
 * 
 * Re-exports all hook factories and their types for the ClawGuard plugin.
 */

// Message Shield Hook
export { 
  createMessageShieldHook,
  type MessageHookContext,
  type MessageHookResult,
} from './message-shield';

// Tool Guard Hook
export {
  createToolGuardHook,
  type ToolHookContext,
  type ToolHookResult,
  type ApprovalRequest,
} from './tool-guard';

// File Watch Hook
export {
  createFileWatchHook,
  type FileHookContext,
  type FileHookResult,
  type EnclaveApprovalRequest,
} from './file-watch';
