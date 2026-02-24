/**
 * Local type definitions that mirror the real OpenClaw Plugin SDK.
 *
 * These are defined locally to avoid a hard dependency on the openclaw package
 * at build time. They are kept in sync with the real types in:
 *   openclaw/openclaw: src/plugins/types.ts
 *
 * Last synced: 2026-02-23 against openclaw@2026.2.21
 */

// ── Logger ────────────────────────────────────────────────────────────────────

export interface PluginLogger {
  /** Optional — not all runtimes provide a debug level. Use logger.debug?.() */
  debug?: (message: string, data?: Record<string, unknown>) => void;
  info(message: string, data?: Record<string, unknown>): void;
  warn(message: string, data?: Record<string, unknown>): void;
  error(message: string, data?: Record<string, unknown>): void;
}

// ── Config ────────────────────────────────────────────────────────────────────

export interface OpenClawConfig {
  workspace?: {
    dir?: string;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

// ── CLI ───────────────────────────────────────────────────────────────────────

export interface OpenClawPluginCliContext {
  program: unknown;
  config: OpenClawConfig;
  workspaceDir?: string;
  logger: PluginLogger;
}

export type OpenClawPluginCliRegistrar = (ctx: OpenClawPluginCliContext) => void | Promise<void>;

// ── Runtime ───────────────────────────────────────────────────────────────────

/** Partial runtime surface exposed to plugins. */
export interface PluginRuntime {
  tools?: unknown[];
  [key: string]: unknown;
}

// ── Hooks ─────────────────────────────────────────────────────────────────────

export type PluginHookName =
  | 'before_model_resolve'
  | 'before_prompt_build'
  | 'before_agent_start'
  | 'llm_input'
  | 'llm_output'
  | 'agent_end'
  | 'before_compaction'
  | 'after_compaction'
  | 'before_reset'
  | 'message_received'
  | 'message_sending'
  | 'message_sent'
  | 'before_tool_call'
  | 'after_tool_call'
  | 'tool_result_persist'
  | 'before_message_write'
  | 'session_start'
  | 'session_end'
  | 'subagent_spawning'
  | 'subagent_delivery_target'
  | 'subagent_spawned'
  | 'subagent_ended'
  | 'gateway_start'
  | 'gateway_stop';

// ── Hook event shapes ─────────────────────────────────────────────────────────

export interface PluginHookMessageContext {
  channelId: string;
  accountId?: string;
  conversationId?: string;
}

export interface PluginHookMessageReceivedEvent {
  from: string;
  content: string;
  timestamp?: number;
  metadata?: Record<string, unknown>;
}

export interface PluginHookMessageSendingEvent {
  to: string;
  content: string;
  metadata?: Record<string, unknown>;
}

export interface PluginHookMessageSendingResult {
  content?: string;
  cancel?: boolean;
}

export interface PluginHookToolContext {
  agentId?: string;
  sessionKey?: string;
  toolName: string;
}

export interface PluginHookBeforeToolCallEvent {
  toolName: string;
  params: Record<string, unknown>;
}

/**
 * Return this from a before_tool_call handler to modify or block a tool call.
 * Returning { block: true, blockReason: '...' } will prevent the tool from running.
 */
export interface PluginHookBeforeToolCallResult {
  /** Modified params (optional override) */
  params?: Record<string, unknown>;
  /** If true, the tool call is blocked and not executed */
  block?: boolean;
  /** Human-readable reason for the block */
  blockReason?: string;
}

// ── Hook handler map ──────────────────────────────────────────────────────────

/**
 * Typed handler map for all OpenClaw lifecycle hooks.
 *
 * Each handler receives (event, ctx) — the second argument is a context object
 * specific to the hook category (agent, message, tool, session, etc.).
 *
 * Key return-value hooks (modifying hooks — results are collected and applied):
 *   before_tool_call → PluginHookBeforeToolCallResult (block/modify tool calls)
 *   message_sending  → PluginHookMessageSendingResult (modify/cancel outgoing messages)
 *
 * All other hooks are fire-and-forget (void).
 */
export type PluginHookHandlerMap = {
  message_received: (
    event: PluginHookMessageReceivedEvent,
    ctx: PluginHookMessageContext,
  ) => Promise<void> | void;

  message_sending: (
    event: PluginHookMessageSendingEvent,
    ctx: PluginHookMessageContext,
  ) =>
    | Promise<PluginHookMessageSendingResult | void>
    | PluginHookMessageSendingResult
    | void;

  before_tool_call: (
    event: PluginHookBeforeToolCallEvent,
    ctx: PluginHookToolContext,
  ) =>
    | Promise<PluginHookBeforeToolCallResult | void>
    | PluginHookBeforeToolCallResult
    | void;

  after_tool_call: (
    event: PluginHookBeforeToolCallEvent & { result?: unknown; error?: string; durationMs?: number },
    ctx: PluginHookToolContext,
  ) => Promise<void> | void;
} & Record<string, (event: unknown, ctx: unknown) => Promise<unknown> | unknown>;

// ── Service ───────────────────────────────────────────────────────────────────

export interface OpenClawPluginServiceContext {
  config: OpenClawConfig;
  workspaceDir?: string;
  stateDir: string;
  logger: PluginLogger;
}

export interface OpenClawPluginService {
  id: string;
  start: (ctx: OpenClawPluginServiceContext) => void | Promise<void>;
  stop?: (ctx: OpenClawPluginServiceContext) => void | Promise<void>;
}

// ── Plugin API ────────────────────────────────────────────────────────────────

/**
 * The real OpenClaw plugin API as exposed to plugin register() functions.
 *
 * Key differences from ClawGuard's original hypothetical interface:
 *   - api.config        → full OpenClawConfig object  (was: api.getConfig())
 *   - api.pluginConfig  → plugin-specific config      (was: api.getConfig())
 *   - api.logger.*()    → structured logger           (was: api.log())
 *   - api.resolvePath() → resolve workspace paths     (was: api.getWorkspacePath())
 *   - api.on()          → typed lifecycle hooks       (was: api.registerHook())
 *   - api.runtime       → plugin runtime surface      (new)
 *
 * BLOCKING tool calls:
 *   Return { block: true, blockReason: '...' } from a before_tool_call handler
 *   and OpenClaw will prevent the tool from executing. This is the preferred
 *   way for ClawGuard to enforce hard-block policies.
 */
export interface OpenClawPluginApi {
  /** Plugin ID */
  id: string;
  /** Plugin name */
  name: string;
  /** Plugin version */
  version?: string;
  /** Plugin description */
  description?: string;
  /** Source path */
  source: string;
  /** Full OpenClaw configuration */
  config: OpenClawConfig;
  /** Plugin-specific configuration (from openclaw.json plugins.<id>) */
  pluginConfig?: Record<string, unknown>;
  /** Plugin runtime surface (tools, session context, etc.) */
  runtime: PluginRuntime;
  /** Structured logger */
  logger: PluginLogger;
  /** Register a tool with the agent */
  registerTool: (tool: unknown, opts?: { optional?: boolean; names?: string[] }) => void;
  /** Register internal string-based hooks */
  registerHook: (
    events: string | string[],
    handler: (...args: unknown[]) => unknown,
    opts?: { priority?: number; entry?: string; name?: string; description?: string },
  ) => void;
  /** Register a typed lifecycle hook */
  on: <K extends PluginHookName>(
    hookName: K,
    handler: PluginHookHandlerMap[K],
    opts?: { priority?: number },
  ) => void;
  /** Register an HTTP request handler (raw) */
  registerHttpHandler: (handler: (req: unknown, res: unknown) => boolean | Promise<boolean>) => void;
  /** Register a named HTTP route */
  registerHttpRoute: (params: {
    path: string;
    handler: (req: unknown, res: unknown) => void | Promise<void>;
  }) => void;
  /** Register CLI commands */
  registerCli: (registrar: OpenClawPluginCliRegistrar, opts?: { commands?: string[] }) => void;
  /** Register a background service */
  registerService: (service: OpenClawPluginService) => void;
  /** Register a provider (auth, models) */
  registerProvider: (provider: unknown) => void;
  /** Register a channel plugin */
  registerChannel: (registration: unknown) => void;
  /** Register a custom slash command */
  registerCommand: (command: {
    name: string;
    description: string;
    acceptsArgs?: boolean;
    requireAuth?: boolean;
    handler: (ctx: unknown) => unknown | Promise<unknown>;
  }) => void;
  /** Resolve a path relative to workspace */
  resolvePath: (input: string) => string;
}
