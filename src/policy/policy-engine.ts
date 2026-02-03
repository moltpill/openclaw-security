/**
 * Policy Engine
 * 
 * Manages security policies from YAML configuration.
 * Evaluates requests against policies and returns actions.
 */

import * as fs from 'fs';
import * as path from 'path';
import YAML from 'yaml';
import { 
  PolicyConfig, 
  PolicyAction,
  ShieldPolicy,
  ScannerPolicy,
  EnclavePolicy,
  ChannelPolicy,
  ToolPolicy,
  AuditPolicy,
  SelfModificationPolicy,
  ThreatLevel
} from '../types';

export interface PolicyEngineOptions {
  configPath?: string;
  config?: Partial<PolicyConfig>;
}

export interface PolicyDecision {
  action: PolicyAction;
  reason: string;
  metadata?: Record<string, unknown>;
}

export class PolicyEngine {
  private config: PolicyConfig;
  private configPath?: string;

  constructor(options: PolicyEngineOptions = {}) {
    this.configPath = options.configPath;
    this.config = this.getDefaultConfig();
    
    if (options.config) {
      this.mergeConfig(options.config);
    }
  }

  /**
   * Load policy from YAML file
   */
  async loadFromFile(filePath?: string): Promise<void> {
    const configFile = filePath || this.configPath;
    
    if (!configFile) {
      throw new Error('No config file path specified');
    }

    try {
      const content = await fs.promises.readFile(configFile, 'utf-8');
      const parsed = YAML.parse(content) as Partial<PolicyConfig>;
      this.mergeConfig(parsed);
      this.configPath = configFile;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        // File doesn't exist, use defaults
        return;
      }
      throw error;
    }
  }

  /**
   * Save current policy to YAML file
   */
  async saveToFile(filePath?: string): Promise<void> {
    const configFile = filePath || this.configPath;
    
    if (!configFile) {
      throw new Error('No config file path specified');
    }

    const content = YAML.stringify(this.config, {
      indent: 2,
      lineWidth: 100
    });

    await fs.promises.mkdir(path.dirname(configFile), { recursive: true });
    await fs.promises.writeFile(configFile, content, 'utf-8');
  }

  /**
   * Evaluate a shield scan result
   */
  evaluateShield(threatLevel: ThreatLevel): PolicyDecision {
    const policy = this.config.shield;
    
    if (!policy?.enabled) {
      return { action: 'allow', reason: 'Shield is disabled' };
    }

    let action: PolicyAction;
    switch (threatLevel) {
      case ThreatLevel.NONE:
      case ThreatLevel.LOW:
        action = policy.actions.onLow;
        break;
      case ThreatLevel.MEDIUM:
        action = policy.actions.onMedium;
        break;
      case ThreatLevel.HIGH:
        action = policy.actions.onHigh;
        break;
      case ThreatLevel.CRITICAL:
        action = policy.actions.onCritical;
        break;
      default:
        action = 'block';
    }

    return {
      action,
      reason: `Threat level ${ThreatLevel[threatLevel]} -> action: ${action}`,
      metadata: { threatLevel, sensitivity: policy.sensitivity }
    };
  }

  /**
   * Evaluate a scanner result
   */
  evaluateScanner(
    operation: 'read' | 'write' | 'existing',
    hasSecrets: boolean
  ): PolicyDecision {
    const policy = this.config.scanner;
    
    if (!policy?.enabled) {
      return { action: 'allow', reason: 'Scanner is disabled' };
    }

    if (!hasSecrets) {
      return { action: 'allow', reason: 'No secrets detected' };
    }

    let action: PolicyAction;
    switch (operation) {
      case 'read':
        action = policy.actions.onRead as PolicyAction;
        break;
      case 'write':
        action = policy.actions.onWrite as PolicyAction;
        break;
      case 'existing':
        action = policy.actions.onExisting === 'quarantine' 
          ? 'quarantine' 
          : policy.actions.onExisting === 'report' 
            ? 'warn' 
            : 'allow';
        break;
      default:
        action = 'warn';
    }

    return {
      action,
      reason: `Secrets detected on ${operation} operation`,
      metadata: { operation }
    };
  }

  /**
   * Evaluate channel access
   */
  evaluateChannel(
    channel: string,
    contactId?: string
  ): PolicyDecision {
    const policy = this.config.channels?.[channel];
    
    if (!policy) {
      // No specific policy for this channel, allow by default
      return { action: 'allow', reason: 'No channel policy defined' };
    }

    // Check blocked contacts
    if (contactId && policy.blockedContacts?.includes(contactId)) {
      return { 
        action: 'block', 
        reason: 'Contact is blocked',
        metadata: { channel, contactId }
      };
    }

    // Check allowed contacts
    if (policy.allowedContacts && contactId) {
      if (!policy.allowedContacts.includes(contactId)) {
        if (!policy.allowUnknown) {
          return { 
            action: 'block', 
            reason: 'Contact not in allowlist',
            metadata: { channel, contactId }
          };
        }
        if (policy.quarantineUnknown) {
          return {
            action: 'quarantine',
            reason: 'Unknown contact quarantined',
            metadata: { channel, contactId }
          };
        }
      }
    }

    return { action: 'allow', reason: 'Channel access permitted' };
  }

  /**
   * Evaluate tool usage
   */
  evaluateTool(
    toolName: string,
    operation?: string,
    target?: string
  ): PolicyDecision {
    const policy = this.config.tools?.[toolName];
    
    if (!policy) {
      // No specific policy, allow by default
      return { action: 'allow', reason: 'No tool policy defined' };
    }

    if (!policy.enabled) {
      return { action: 'block', reason: 'Tool is disabled' };
    }

    // Check blocked patterns
    if (policy.blockedPatterns && target) {
      for (const pattern of policy.blockedPatterns) {
        if (new RegExp(pattern, 'i').test(target)) {
          return {
            action: 'block',
            reason: `Target matches blocked pattern: ${pattern}`,
            metadata: { toolName, pattern, target }
          };
        }
      }
    }

    // Check allowed patterns
    if (policy.allowedPatterns && target) {
      const allowed = policy.allowedPatterns.some(pattern =>
        new RegExp(pattern, 'i').test(target)
      );
      
      if (!allowed) {
        return {
          action: 'block',
          reason: 'Target does not match any allowed pattern',
          metadata: { toolName, target }
        };
      }
    }

    // Check if approval required
    if (policy.requiresApproval) {
      return {
        action: 'require_approval',
        reason: 'Tool requires human approval',
        metadata: { toolName, operation, target }
      };
    }

    return { action: 'allow', reason: 'Tool usage permitted' };
  }

  /**
   * Get the full policy config
   */
  getConfig(): PolicyConfig {
    return { ...this.config };
  }

  /**
   * Get a specific policy section
   */
  getShieldPolicy(): ShieldPolicy | undefined {
    return this.config.shield;
  }

  getScannerPolicy(): ScannerPolicy | undefined {
    return this.config.scanner;
  }

  getEnclavePolicy(): EnclavePolicy | undefined {
    return this.config.enclave;
  }

  getChannelPolicy(channel: string): ChannelPolicy[string] | undefined {
    return this.config.channels?.[channel];
  }

  getToolPolicy(tool: string): ToolPolicy[string] | undefined {
    return this.config.tools?.[tool];
  }

  getAuditPolicy(): AuditPolicy | undefined {
    return this.config.audit;
  }

  getSelfModificationPolicy(): SelfModificationPolicy | undefined {
    return this.config.selfModification;
  }

  /**
   * Update policy configuration
   */
  updateConfig(config: Partial<PolicyConfig>): void {
    this.mergeConfig(config);
  }

  /**
   * Validate a policy configuration
   */
  validate(config: Partial<PolicyConfig>): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    // Validate shield policy
    if (config.shield) {
      if (config.shield.sensitivity && 
          !['low', 'medium', 'high'].includes(config.shield.sensitivity)) {
        errors.push('Shield sensitivity must be low, medium, or high');
      }
    }

    // Validate scanner policy
    if (config.scanner) {
      if (config.scanner.actions) {
        const validReadActions = ['allow', 'warn', 'redact', 'block'];
        const validWriteActions = ['allow', 'warn', 'block'];
        const validExistingActions = ['report', 'quarantine'];

        if (config.scanner.actions.onRead && 
            !validReadActions.includes(config.scanner.actions.onRead)) {
          errors.push('Scanner onRead action must be: allow, warn, redact, or block');
        }
        if (config.scanner.actions.onWrite && 
            !validWriteActions.includes(config.scanner.actions.onWrite)) {
          errors.push('Scanner onWrite action must be: allow, warn, or block');
        }
        if (config.scanner.actions.onExisting && 
            !validExistingActions.includes(config.scanner.actions.onExisting)) {
          errors.push('Scanner onExisting action must be: report or quarantine');
        }
      }
    }

    // Validate enclave policy
    if (config.enclave) {
      if (config.enclave.approval?.timeoutMs !== undefined && 
          config.enclave.approval.timeoutMs < 1000) {
        errors.push('Enclave approval timeout must be at least 1000ms');
      }
    }

    return { valid: errors.length === 0, errors };
  }

  // ============ Private Methods ============

  private getDefaultConfig(): PolicyConfig {
    return {
      shield: {
        enabled: true,
        sensitivity: 'medium',
        customPatterns: [],
        allowlist: [],
        actions: {
          onLow: 'allow',
          onMedium: 'warn',
          onHigh: 'block',
          onCritical: 'block'
        }
      },
      scanner: {
        enabled: true,
        scanOnStartup: true,
        extensions: ['.md', '.yaml', '.yml', '.json', '.env', '.txt'],
        excludePaths: ['node_modules/', '.git/', 'dist/'],
        customPatterns: [],
        actions: {
          onRead: 'warn',
          onWrite: 'block',
          onExisting: 'report'
        }
      },
      enclave: {
        enabled: true,
        path: '~/.openclaw/enclave',
        protectedFiles: ['SOUL.md', 'IDENTITY.md', 'secrets/*'],
        approval: {
          channel: 'whatsapp',
          timeoutMs: 24 * 60 * 60 * 1000,
          requireReason: true,
          showDiff: true
        },
        summaries: {}
      },
      channels: {},
      tools: {},
      audit: {
        enabled: true,
        logPath: '~/.openclaw/logs/clawguard',
        retentionDays: 30,
        logLevel: 'standard',
        includeContent: false
      }
    };
  }

  private mergeConfig(config: Partial<PolicyConfig>): void {
    if (config.shield) {
      this.config.shield = { ...this.config.shield, ...config.shield };
      if (config.shield.actions) {
        this.config.shield!.actions = { 
          ...this.config.shield!.actions, 
          ...config.shield.actions 
        };
      }
    }

    if (config.scanner) {
      this.config.scanner = { ...this.config.scanner, ...config.scanner };
      if (config.scanner.actions) {
        this.config.scanner!.actions = { 
          ...this.config.scanner!.actions, 
          ...config.scanner.actions 
        };
      }
    }

    if (config.enclave) {
      this.config.enclave = { ...this.config.enclave, ...config.enclave };
      if (config.enclave.approval) {
        this.config.enclave!.approval = { 
          ...this.config.enclave!.approval, 
          ...config.enclave.approval 
        };
      }
    }

    if (config.channels) {
      this.config.channels = { ...this.config.channels, ...config.channels };
    }

    if (config.tools) {
      this.config.tools = { ...this.config.tools, ...config.tools };
    }

    if (config.audit) {
      this.config.audit = { ...this.config.audit, ...config.audit };
    }
  }
}

/**
 * Generate a sample policy YAML configuration
 */
export function generateSamplePolicy(): string {
  return `# ClawGuard Security Policy
# See documentation for all options

# Injection Shield Configuration
shield:
  enabled: true
  sensitivity: medium  # low, medium, high
  allowlist: []
  actions:
    onLow: allow
    onMedium: warn
    onHigh: block
    onCritical: block

# Secret Scanner Configuration
scanner:
  enabled: true
  scanOnStartup: true
  extensions:
    - .md
    - .yaml
    - .yml
    - .json
    - .env
    - .txt
  excludePaths:
    - node_modules/
    - .git/
    - dist/
  actions:
    onRead: warn      # allow, warn, redact, block
    onWrite: block    # allow, warn, block
    onExisting: report # report, quarantine

# Secure Enclave Configuration
enclave:
  enabled: true
  path: ~/.openclaw/enclave
  protectedFiles:
    - SOUL.md
    - IDENTITY.md
    - secrets/*
  approval:
    channel: whatsapp
    timeoutMs: 86400000  # 24 hours
    requireReason: true
    showDiff: true
  summaries:
    SOUL.md: "Defines agent personality and boundaries"
    IDENTITY.md: "Agent name and identity information"

# Channel Policies
channels:
  whatsapp:
    allowedContacts: []  # Empty = allow all
    allowUnknown: true
    quarantineUnknown: false
    rateLimit:
      maxPerHour: 100
      maxPerDay: 1000

# Tool Policies
tools:
  exec:
    enabled: true
    requiresApproval: false
    blockedPatterns:
      - "rm -rf"
      - "sudo"
  message:
    enabled: true
    requiresApproval: false

# Audit Logging
audit:
  enabled: true
  logPath: ~/.openclaw/logs/clawguard
  retentionDays: 30
  logLevel: standard  # minimal, standard, verbose
  includeContent: false
`;
}
