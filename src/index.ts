/**
 * ClawGuard - Security layer for OpenClaw
 * 
 * Protects against prompt injection, secures sensitive files,
 * and provides audit logging for AI agent activity.
 */

export * from './types';

// Shield - Pattern-based injection detection
export { InjectionShield } from './shield/injection-shield';
export type { ShieldOptions, ScanContext } from './shield/injection-shield';

// ML Detection - Machine learning based injection detection
export { MLDetector } from './shield/ml-detector';
export type { MLDetectorConfig, MLScanResult } from './shield/ml-detector';

// Hybrid Shield - Combined pattern + ML detection
export { HybridShield, createHybridShield } from './shield/hybrid-shield';
export type { HybridShieldConfig, HybridScanResult, MLStrategy } from './shield/hybrid-shield';

// Training Data - Examples for ML training
export { 
  INJECTION_EXAMPLES, 
  BENIGN_EXAMPLES,
  getAllExamples,
  getInjectionTexts,
  getBenignTexts
} from './shield/training-data';
export type { TrainingExample } from './shield/training-data';

// Other modules
export { SecretScanner } from './scanner/secret-scanner';
export { SecureEnclave } from './enclave/secure-enclave';
export { PolicyEngine } from './policy/policy-engine';
export { AuditLogger } from './audit/audit-logger';
export { ClawGuard, createClawGuard } from './clawguard';

// Self-Modification Guard - Prevents agents from modifying own installation
export { SelfModificationGuard } from './guards/self-modification-guard';
export type { 
  SelfModificationPolicy, 
  SelfModificationCheckResult,
  SelfModificationCategory 
} from './guards/self-modification-guard';

// Approval workflow
export { ApprovalChannel, ApprovalManager } from './approval';
export type {
  ApprovalChannelConfig,
  ApprovalTemplates,
  PendingApproval,
  ApprovalResponse,
  MessageCommand,
  ApprovalManagerConfig,
  RequestApprovalResult,
  ProcessResponseResult
} from './approval';

// OpenClaw Plugin
export { 
  clawguardPlugin, 
  clawguardPlugin as default 
} from './plugin';
export type { 
  OpenClawPluginApi,
  PluginRegistrationResult,
  ClawGuardPluginConfig 
} from './plugin';
export { 
  ClawGuardPluginConfigSchema, 
  DEFAULT_CONFIG, 
  resolveConfig,
  BLOCKED_CATEGORIES,
  type BlockedCategory,
  type ClawGuardPluginConfigInput,
} from './plugin/config';
