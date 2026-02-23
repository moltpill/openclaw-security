/**
 * Plugin Hooks Index
 *
 * Re-exports all hook factories and their event types for the ClawGuard plugin.
 *
 * Hook names updated to match the real OpenClaw SDK:
 *   message:before → message_received
 *   tool:before    → before_tool_call
 *   file:before    → before_tool_call (filtered for file tools)
 *
 * Return types:
 *   createToolGuardHook and createFileWatchHook return
 *   PluginHookBeforeToolCallResult | void, enabling actual blocking via the SDK.
 */

export {
  createMessageShieldHook,
  type MessageReceivedEvent,
} from './message-shield';

export {
  createToolGuardHook,
  type BeforeToolCallEvent,
} from './tool-guard';

export {
  createFileWatchHook,
} from './file-watch';
