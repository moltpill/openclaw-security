/**
 * ClawGuard - Main Security Layer
 * 
 * Integrates all security components into a unified interface
 * for protecting OpenClaw agents.
 */

import { InjectionShield, ScanContext } from './shield/injection-shield';
import { SecretScanner } from './scanner/secret-scanner';
import { SecureEnclave } from './enclave/secure-enclave';
import { PolicyEngine } from './policy/policy-engine';
import { AuditLogger } from './audit/audit-logger';
import { SelfModificationGuard, SelfModificationCheckResult, SelfModificationPolicy } from './guards/self-modification-guard';
import { 
  PolicyConfig, 
  ScanResult, 
  ThreatLevel,
  PolicyAction,
  EnclaveChangeRequest 
} from './types';

export interface ClawGuardOptions {
  configPath?: string;
  config?: Partial<PolicyConfig>;
  enclavePath?: string;
  logPath?: string;
}

export interface MessageScanResult extends ScanResult {
  action: PolicyAction;
  redactedContent?: string;
}

export interface ToolCheckResult {
  allowed: boolean;
  action: PolicyAction;
  reason: string;
  requiresApproval: boolean;
}

export class ClawGuard {
  readonly shield: InjectionShield;
  readonly scanner: SecretScanner;
  readonly enclave: SecureEnclave;
  readonly policy: PolicyEngine;
  readonly audit: AuditLogger;
  readonly selfMod: SelfModificationGuard;

  private initialized = false;

  constructor(options: ClawGuardOptions = {}) {
    // Initialize policy engine first
    this.policy = new PolicyEngine({
      configPath: options.configPath,
      config: options.config
    });

    // Initialize components with policy
    this.shield = new InjectionShield({
      policy: this.policy.getShieldPolicy()
    });

    this.scanner = new SecretScanner({
      policy: this.policy.getScannerPolicy()
    });

    this.enclave = new SecureEnclave({
      policy: {
        ...this.policy.getEnclavePolicy(),
        path: options.enclavePath || this.policy.getEnclavePolicy()?.path
      }
    });

    this.audit = new AuditLogger({
      policy: {
        ...this.policy.getAuditPolicy(),
        logPath: options.logPath || this.policy.getAuditPolicy()?.logPath
      }
    });

    // Initialize self-modification guard
    this.selfMod = new SelfModificationGuard(
      this.policy.getSelfModificationPolicy?.() || {}
    );
  }

  /**
   * Initialize ClawGuard (async setup)
   */
  async initialize(): Promise<void> {
    if (this.initialized) return;

    // Load config if path specified
    await this.policy.loadFromFile().catch(() => {});

    // Initialize enclave
    await this.enclave.initialize();

    // Run startup scan if enabled
    const scannerPolicy = this.policy.getScannerPolicy();
    if (scannerPolicy?.scanOnStartup) {
      await this.runStartupScan();
    }

    this.initialized = true;

    this.audit.logConfigChange({
      section: 'startup',
      changes: { initialized: true }
    });
  }

  /**
   * Scan an inbound message for threats
   */
  scanMessage(
    content: string,
    context?: {
      channel?: string;
      senderId?: string;
      isExternal?: boolean;
      sessionId?: string;
    }
  ): MessageScanResult {
    // Run injection detection
    const scanContext: ScanContext = {
      sourceId: context?.senderId,
      isExternalContent: context?.isExternal ?? true,
      channel: context?.channel
    };

    const shieldResult = this.shield.scan(content, scanContext);

    // Evaluate policy
    const policyDecision = this.policy.evaluateShield(shieldResult.threatLevel);

    // Check for secrets in message
    const secretResult = this.scanner.scan(content);

    // Combine results
    const combinedThreats = [...shieldResult.threats, ...secretResult.threats];
    const maxThreatLevel = Math.max(shieldResult.threatLevel, secretResult.threatLevel);

    // Determine final action
    let action = policyDecision.action;
    if (secretResult.threats.length > 0) {
      const secretDecision = this.policy.evaluateScanner('read', true);
      if (secretDecision.action === 'block') {
        action = 'block';
      } else if (secretDecision.action === 'warn' && action === 'allow') {
        action = 'warn';
      }
    }

    // Log the scan
    this.audit.logMessageInbound({
      channel: context?.channel || 'unknown',
      senderId: context?.senderId,
      contentHash: this.hashContent(content),
      threatIndicators: combinedThreats.length > 0 ? combinedThreats : undefined,
      sessionId: context?.sessionId
    });

    if (combinedThreats.length > 0) {
      this.audit.logThreatDetected({
        source: context?.channel || 'message',
        threats: combinedThreats,
        action: action,
        sessionId: context?.sessionId
      });
    }

    // Prepare result
    const result: MessageScanResult = {
      safe: maxThreatLevel <= ThreatLevel.LOW && action === 'allow',
      threatLevel: maxThreatLevel,
      threats: combinedThreats,
      action,
      metadata: {
        ...shieldResult.metadata,
        secretsFound: secretResult.threats.length
      }
    };

    // Redact if needed
    if (action === 'warn' && secretResult.threats.length > 0) {
      const { redacted } = this.scanner.redact(content);
      result.redactedContent = redacted;
    }

    return result;
  }

  /**
   * Check if a tool invocation is allowed
   */
  checkTool(
    tool: string,
    operation?: string,
    target?: string,
    sessionId?: string
  ): ToolCheckResult {
    const decision = this.policy.evaluateTool(tool, operation, target);

    // Log the check
    this.audit.logToolInvocation({
      tool,
      operation,
      target,
      allowed: decision.action === 'allow' || decision.action === 'require_approval',
      reason: decision.reason,
      sessionId
    });

    return {
      allowed: decision.action === 'allow',
      action: decision.action,
      reason: decision.reason,
      requiresApproval: decision.action === 'require_approval'
    };
  }

  /**
   * Scan file content for secrets
   */
  scanContent(content: string, operation: 'read' | 'write' = 'read'): {
    safe: boolean;
    action: PolicyAction;
    redactedContent?: string;
  } {
    const result = this.scanner.scan(content);
    const decision = this.policy.evaluateScanner(operation, result.threats.length > 0);

    let redactedContent: string | undefined;
    // Scanner actions include 'redact' but PolicyAction doesn't - check the raw action string
    const scannerAction = this.policy.getScannerPolicy()?.actions.onRead;
    if (scannerAction === 'redact' || (decision.action === 'warn' && result.threats.length > 0)) {
      const { redacted } = this.scanner.redact(content);
      redactedContent = redacted;
    }

    return {
      safe: result.safe,
      action: decision.action,
      redactedContent
    };
  }

  /**
   * Check channel access
   */
  checkChannel(channel: string, contactId?: string): {
    allowed: boolean;
    action: PolicyAction;
    reason: string;
  } {
    const decision = this.policy.evaluateChannel(channel, contactId);
    
    return {
      allowed: decision.action === 'allow',
      action: decision.action,
      reason: decision.reason
    };
  }

  /**
   * Check if a command would modify the agent's own installation
   * 
   * Use this before executing ANY shell command to prevent:
   * - Self-update attempts (npm install openclaw)
   * - Removing own installation (rm -rf node_modules/openclaw)
   * - Gateway control (openclaw gateway restart/stop)
   * - Config tampering
   * - Process termination
   */
  checkSelfModification(command: string, sessionId?: string): SelfModificationCheckResult {
    const result = this.selfMod.check(command);

    // Log if blocked or requires approval
    if (result.blocked || result.requiresApproval) {
      this.audit.logToolInvocation({
        tool: 'exec',
        operation: 'self-modification-blocked',
        target: command,
        allowed: false,
        reason: result.reason,
        sessionId
      });
    }

    return result;
  }

  /**
   * Check multiple commands (e.g., from a script)
   */
  checkScriptForSelfModification(commands: string[]): SelfModificationCheckResult[] {
    return this.selfMod.checkScript(commands);
  }

  /**
   * Check if a file is protected by enclave
   */
  isProtectedFile(filePath: string): boolean {
    return this.enclave.isProtected(filePath);
  }

  /**
   * Request a change to a protected file
   */
  async requestEnclaveChange(
    file: string,
    newContent: string,
    reason: string,
    sessionId?: string
  ): Promise<{
    success: boolean;
    requestId?: string;
    error?: string;
    approvalMessage?: string;
  }> {
    const result = await this.enclave.requestChange(file, newContent, reason);

    if (result.success && result.requestId) {
      const request = this.enclave.getRequestStatus(result.requestId);
      
      this.audit.logEnclaveRequest({
        requestId: result.requestId,
        file,
        reason,
        sessionId
      });

      const approvalMessage = request 
        ? this.enclave.formatRequestForApproval(request)
        : undefined;

      return {
        success: true,
        requestId: result.requestId,
        approvalMessage
      };
    }

    return result;
  }

  /**
   * Get pending enclave requests
   */
  getPendingEnclaveRequests(): EnclaveChangeRequest[] {
    return this.enclave.getPendingRequests();
  }

  /**
   * Process an enclave approval response
   */
  async processEnclaveApproval(
    requestId: string,
    approved: boolean,
    reviewedBy: string,
    sessionId?: string
  ): Promise<{ success: boolean; error?: string }> {
    let result;
    
    if (approved) {
      result = await this.enclave.approveRequest(requestId, reviewedBy);
    } else {
      result = await this.enclave.denyRequest(requestId, reviewedBy);
    }

    this.audit.logEnclaveDecision({
      requestId,
      decision: approved ? 'approved' : 'denied',
      reviewedBy,
      sessionId
    });

    return result;
  }

  /**
   * Get a summary of a protected file (safe for agent)
   */
  getFileSummary(fileName: string): string | undefined {
    return this.enclave.getSummary(fileName);
  }

  /**
   * List protected files
   */
  async listProtectedFiles() {
    return this.enclave.listFiles();
  }

  /**
   * Get recent audit logs
   */
  async getAuditLogs(options?: {
    limit?: number;
    since?: Date;
    sessionId?: string;
  }) {
    return this.audit.getRecentLogs(options);
  }

  /**
   * Get security statistics
   */
  async getStats(since?: Date) {
    return this.audit.getStats(since);
  }

  /**
   * Update configuration
   */
  async updateConfig(config: Partial<PolicyConfig>): Promise<void> {
    const validation = this.policy.validate(config);
    if (!validation.valid) {
      throw new Error(`Invalid config: ${validation.errors.join(', ')}`);
    }

    this.policy.updateConfig(config);

    // Update component policies
    if (config.shield) {
      this.shield.updatePolicy(config.shield);
    }
    if (config.scanner) {
      this.scanner.updatePolicy(config.scanner);
    }
    if (config.enclave) {
      this.enclave.updatePolicy(config.enclave);
    }
    if (config.audit) {
      this.audit.updatePolicy(config.audit);
    }

    this.audit.logConfigChange({
      section: 'policy',
      changes: config
    });
  }

  /**
   * Save current configuration
   */
  async saveConfig(filePath?: string): Promise<void> {
    await this.policy.saveToFile(filePath);
  }

  /**
   * Stop ClawGuard (cleanup)
   */
  async stop(): Promise<void> {
    await this.audit.stop();
  }

  // ============ Private Methods ============

  private async runStartupScan(): Promise<void> {
    const workspacePath = process.env.OPENCLAW_WORKSPACE || process.cwd();
    const results = await this.scanner.scanDirectory(workspacePath);

    for (const result of results) {
      if (result.threats.length > 0) {
        this.audit.logSecretDetected({
          filePath: result.filePath,
          secretType: result.threats[0].pattern || 'unknown',
          action: this.policy.getScannerPolicy()?.actions.onExisting || 'report',
          redacted: false
        });
      }
    }
  }

  private hashContent(content: string): string {
    // Simple hash for logging (not cryptographic)
    let hash = 0;
    for (let i = 0; i < content.length; i++) {
      const char = content.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return Math.abs(hash).toString(16);
  }
}

/**
 * Create and initialize a ClawGuard instance
 */
export async function createClawGuard(options?: ClawGuardOptions): Promise<ClawGuard> {
  const guard = new ClawGuard(options);
  await guard.initialize();
  return guard;
}
