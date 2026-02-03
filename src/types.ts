/**
 * ClawGuard Core Types
 */

// Threat levels for detected issues
export enum ThreatLevel {
  NONE = 0,
  LOW = 1,
  MEDIUM = 2,
  HIGH = 3,
  CRITICAL = 4
}

// Result of scanning content for threats
export interface ScanResult {
  safe: boolean;
  threatLevel: ThreatLevel;
  threats: Threat[];
  metadata: Record<string, unknown>;
}

// Individual threat detection
export interface Threat {
  type: ThreatType;
  severity: ThreatLevel;
  description: string;
  location?: {
    start: number;
    end: number;
    line?: number;
  };
  pattern?: string;
  confidence: number; // 0-1
}

export enum ThreatType {
  // Injection threats
  PROMPT_INJECTION = 'prompt_injection',
  INSTRUCTION_OVERRIDE = 'instruction_override',
  ROLE_HIJACK = 'role_hijack',
  
  // Secret threats
  API_KEY = 'api_key',
  PRIVATE_KEY = 'private_key',
  PASSWORD = 'password',
  TOKEN = 'token',
  CONNECTION_STRING = 'connection_string',
  
  // Channel threats
  UNKNOWN_SENDER = 'unknown_sender',
  SPOOFED_IDENTITY = 'spoofed_identity',
  RATE_LIMIT_EXCEEDED = 'rate_limit_exceeded',
  
  // Other
  SUSPICIOUS_PATTERN = 'suspicious_pattern',
  POLICY_VIOLATION = 'policy_violation'
}

// Policy configuration
export interface PolicyConfig {
  shield?: ShieldPolicy;
  scanner?: ScannerPolicy;
  enclave?: EnclavePolicy;
  channels?: ChannelPolicy;
  tools?: ToolPolicy;
  audit?: AuditPolicy;
  selfModification?: SelfModificationPolicy;
}

export interface SelfModificationPolicy {
  enabled: boolean;
  blockInstall: boolean;
  blockUninstall: boolean;
  blockGatewayControl: boolean;
  blockConfigEdit: boolean;
  blockProcessKill: boolean;
  requireApproval: boolean;
  customPatterns?: string[];
}

export interface ShieldPolicy {
  enabled: boolean;
  sensitivity: 'low' | 'medium' | 'high';
  customPatterns?: PatternDef[];
  allowlist?: string[];
  actions: {
    onLow: PolicyAction;
    onMedium: PolicyAction;
    onHigh: PolicyAction;
    onCritical: PolicyAction;
  };
}

export interface ScannerPolicy {
  enabled: boolean;
  scanOnStartup: boolean;
  extensions: string[];
  excludePaths: string[];
  customPatterns?: PatternDef[];
  actions: {
    onRead: 'allow' | 'warn' | 'redact' | 'block';
    onWrite: 'allow' | 'warn' | 'block';
    onExisting: 'report' | 'quarantine';
  };
}

export interface EnclavePolicy {
  enabled: boolean;
  path: string;
  protectedFiles: string[];
  approval: {
    channel: string;
    timeoutMs: number;
    requireReason: boolean;
    showDiff: boolean;
  };
  summaries: Record<string, string>;
}

export interface ChannelPolicy {
  [channel: string]: {
    allowedContacts?: string[];
    blockedContacts?: string[];
    allowUnknown: boolean;
    quarantineUnknown: boolean;
    rateLimit?: {
      maxPerHour: number;
      maxPerDay: number;
    };
  };
}

export interface ToolPolicy {
  [tool: string]: {
    enabled: boolean;
    requiresApproval: boolean;
    allowedPatterns?: string[];
    blockedPatterns?: string[];
    rateLimit?: number;
  };
}

export interface AuditPolicy {
  enabled: boolean;
  logPath: string;
  retentionDays: number;
  logLevel: 'minimal' | 'standard' | 'verbose';
  includeContent: boolean;
}

export interface PatternDef {
  name: string;
  pattern: string; // regex
  severity: ThreatLevel;
  description?: string;
}

export type PolicyAction = 'allow' | 'warn' | 'block' | 'quarantine' | 'require_approval';

// Enclave types
export interface EnclaveChangeRequest {
  id: string;
  file: string;
  diff: string;
  reason: string;
  requestedAt: Date;
  requestedBy: string;
  status: 'pending' | 'approved' | 'denied' | 'expired';
  reviewedAt?: Date;
  reviewedBy?: string;
}

// Audit types
export interface AuditEvent {
  timestamp: Date;
  eventType: AuditEventType;
  sessionId?: string;
  correlationId?: string;
  data: Record<string, unknown>;
  threatIndicators?: Threat[];
}

export enum AuditEventType {
  MESSAGE_INBOUND = 'message_inbound',
  MESSAGE_OUTBOUND = 'message_outbound',
  TOOL_INVOCATION = 'tool_invocation',
  THREAT_DETECTED = 'threat_detected',
  POLICY_DECISION = 'policy_decision',
  ENCLAVE_REQUEST = 'enclave_request',
  ENCLAVE_DECISION = 'enclave_decision',
  SECRET_DETECTED = 'secret_detected',
  CONFIG_CHANGE = 'config_change'
}
