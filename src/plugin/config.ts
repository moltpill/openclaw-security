/**
 * ClawGuard Plugin Configuration Schema
 * 
 * Defines the configuration schema for the OpenClaw plugin using Zod.
 */

import { z } from 'zod';

/**
 * Blocked category enum values
 */
export const BLOCKED_CATEGORIES = [
  'package-management',
  'gateway-control',
  'config-tampering',
  'process-control',
  'file-deletion',
] as const;

export type BlockedCategory = typeof BLOCKED_CATEGORIES[number];

/**
 * Shield (injection detection) configuration
 */
export const ShieldConfigSchema = z.object({
  enabled: z.boolean().default(true),
  sensitivity: z.enum(['low', 'medium', 'high']).default('medium'),
  blockOnDetection: z.boolean().default(false),
  patterns: z.object({
    systemPromptOverride: z.boolean().default(true),
    roleImpersonation: z.boolean().default(true),
    instructionInjection: z.boolean().default(true),
    encodedPayloads: z.boolean().default(true),
  }).optional(),
}).optional();

/**
 * Scanner (secret detection) configuration
 */
export const ScannerConfigSchema = z.object({
  enabled: z.boolean().default(true),
  patterns: z.object({
    apiKeys: z.boolean().default(true),
    passwords: z.boolean().default(true),
    tokens: z.boolean().default(true),
    privateKeys: z.boolean().default(true),
  }).optional(),
  onDetection: z.enum(['block', 'warn', 'redact', 'allow']).default('warn'),
}).optional();

/**
 * Enclave (protected files) configuration
 */
export const EnclaveConfigSchema = z.object({
  enabled: z.boolean().default(true),
  protectedFiles: z.array(z.string()).default([
    'SOUL.md',
    'USER.md',
    'MEMORY.md',
    'secrets/*',
    '.env*',
  ]),
  requireApproval: z.boolean().default(true),
}).optional();

/**
 * Self-modification guard configuration
 */
export const SelfModificationConfigSchema = z.object({
  enabled: z.boolean().default(true),
  requireApproval: z.boolean().default(true),
  blockedCategories: z.array(z.enum(BLOCKED_CATEGORIES)).default(['gateway-control', 'process-control']),
}).optional();

/**
 * Command allowlist configuration
 *
 * Commands matching allowlist patterns bypass self-modification guard
 * and optionally auto-elevate (inject `elevated: true` into exec params).
 *
 * Patterns use glob-like matching: `*` matches anything.
 * Examples:
 *   "tailscale status"         — exact match
 *   "tailscale *"              — any tailscale subcommand
 *   "sudo tailscale *"         — any sudo tailscale command (auto-elevated)
 *   "sudo systemctl restart openclaw-*" — restart our own services
 */
export const AllowlistConfigSchema = z.object({
  enabled: z.boolean().default(true),
  /** Commands that bypass the self-modification guard */
  commands: z.array(z.string()).default([]),
  /** Commands that auto-inject `elevated: true` (for sudo commands) */
  elevate: z.array(z.string()).default([]),
}).optional();

/**
 * Audit logging configuration
 */
export const AuditConfigSchema = z.object({
  enabled: z.boolean().default(true),
  logPath: z.string().optional(),
  retention: z.object({
    maxAgeDays: z.number().default(30),
    maxSizeMb: z.number().default(100),
  }).optional(),
}).optional();

/**
 * Full plugin configuration schema
 */
export const ClawGuardPluginConfigSchema = z.object({
  shield: ShieldConfigSchema,
  scanner: ScannerConfigSchema,
  enclave: EnclaveConfigSchema,
  selfModification: SelfModificationConfigSchema,
  allowlist: AllowlistConfigSchema,
  audit: AuditConfigSchema,
});

/**
 * Input type from schema (with optionals)
 */
export type ClawGuardPluginConfigInput = z.input<typeof ClawGuardPluginConfigSchema>;

/**
 * Resolved config with all defaults applied
 */
export interface ClawGuardPluginConfig {
  shield: {
    enabled: boolean;
    sensitivity: 'low' | 'medium' | 'high';
    blockOnDetection: boolean;
    patterns: {
      systemPromptOverride: boolean;
      roleImpersonation: boolean;
      instructionInjection: boolean;
      encodedPayloads: boolean;
    };
  };
  scanner: {
    enabled: boolean;
    patterns: {
      apiKeys: boolean;
      passwords: boolean;
      tokens: boolean;
      privateKeys: boolean;
    };
    onDetection: 'block' | 'warn' | 'redact' | 'allow';
  };
  enclave: {
    enabled: boolean;
    protectedFiles: string[];
    requireApproval: boolean;
  };
  selfModification: {
    enabled: boolean;
    requireApproval: boolean;
    blockedCategories: BlockedCategory[];
  };
  allowlist: {
    enabled: boolean;
    commands: string[];
    elevate: string[];
  };
  audit: {
    enabled: boolean;
    logPath?: string;
    retention: {
      maxAgeDays: number;
      maxSizeMb: number;
    };
  };
}

/**
 * Default plugin configuration
 */
export const DEFAULT_CONFIG: ClawGuardPluginConfig = {
  shield: {
    enabled: true,
    sensitivity: 'medium',
    blockOnDetection: false,
    patterns: {
      systemPromptOverride: true,
      roleImpersonation: true,
      instructionInjection: true,
      encodedPayloads: true,
    },
  },
  scanner: {
    enabled: true,
    patterns: {
      apiKeys: true,
      passwords: true,
      tokens: true,
      privateKeys: true,
    },
    onDetection: 'warn',
  },
  enclave: {
    enabled: true,
    protectedFiles: [
      'SOUL.md',
      'USER.md',
      'MEMORY.md',
      'secrets/*',
      '.env*',
    ],
    requireApproval: true,
  },
  selfModification: {
    enabled: true,
    requireApproval: true,
    blockedCategories: ['gateway-control', 'process-control'],
  },
  allowlist: {
    enabled: true,
    commands: [],
    elevate: [],
  },
  audit: {
    enabled: true,
    retention: {
      maxAgeDays: 30,
      maxSizeMb: 100,
    },
  },
};

/**
 * Merge user config with defaults
 */
export function resolveConfig(userConfig: ClawGuardPluginConfigInput = {}): ClawGuardPluginConfig {
  return {
    shield: {
      ...DEFAULT_CONFIG.shield,
      ...userConfig.shield,
      patterns: {
        ...DEFAULT_CONFIG.shield.patterns,
        ...userConfig.shield?.patterns,
      },
    },
    scanner: {
      ...DEFAULT_CONFIG.scanner,
      ...userConfig.scanner,
      patterns: {
        ...DEFAULT_CONFIG.scanner.patterns,
        ...userConfig.scanner?.patterns,
      },
    },
    enclave: {
      ...DEFAULT_CONFIG.enclave,
      ...userConfig.enclave,
    },
    selfModification: {
      ...DEFAULT_CONFIG.selfModification,
      ...userConfig.selfModification,
      blockedCategories: userConfig.selfModification?.blockedCategories ?? DEFAULT_CONFIG.selfModification.blockedCategories,
    },
    allowlist: {
      ...DEFAULT_CONFIG.allowlist,
      ...userConfig.allowlist,
      commands: userConfig.allowlist?.commands ?? DEFAULT_CONFIG.allowlist.commands,
      elevate: userConfig.allowlist?.elevate ?? DEFAULT_CONFIG.allowlist.elevate,
    },
    audit: {
      ...DEFAULT_CONFIG.audit,
      ...userConfig.audit,
      retention: {
        ...DEFAULT_CONFIG.audit.retention,
        ...userConfig.audit?.retention,
      },
    },
  };
}

// ============ Workspace Auto-Detection ============

import * as fs from 'fs';
import * as path from 'path';

/**
 * Well-known workspace identity/memory files that should be auto-protected
 */
const WORKSPACE_IDENTITY_FILES = [
  'SOUL.md',
  'USER.md',
  'MEMORY.md',
  'IDENTITY.md',
  'AGENTS.md',
  'TOOLS.md',
  'memory/*.md',
];

/**
 * Detect workspace identity files that exist in the given directory
 */
export function detectWorkspaceFiles(workspacePath: string): string[] {
  const detected: string[] = [];
  
  for (const filePattern of WORKSPACE_IDENTITY_FILES) {
    // Handle glob patterns (simple * matching)
    if (filePattern.includes('*')) {
      const [dir, pattern] = filePattern.split('/');
      const dirPath = path.join(workspacePath, dir);
      
      if (fs.existsSync(dirPath) && fs.statSync(dirPath).isDirectory()) {
        try {
          const files = fs.readdirSync(dirPath);
          const regex = new RegExp(`^${pattern.replace('*', '.*')}$`);
          
          for (const file of files) {
            if (regex.test(file)) {
              detected.push(`${dir}/${file}`);
            }
          }
        } catch {
          // Directory not readable, skip
        }
      }
    } else {
      // Simple file check
      const filePath = path.join(workspacePath, filePattern);
      if (fs.existsSync(filePath)) {
        detected.push(filePattern);
      }
    }
  }
  
  return detected;
}

/**
 * Merge auto-detected files with configured protected files
 */
export function mergeProtectedFiles(
  configuredFiles: string[],
  workspacePath: string
): string[] {
  const detected = detectWorkspaceFiles(workspacePath);
  
  // Use Set to deduplicate
  const allFiles = new Set<string>(configuredFiles);
  
  for (const file of detected) {
    allFiles.add(file);
  }
  
  return Array.from(allFiles);
}

/**
 * Apply workspace auto-detection to config
 */
export function applyWorkspaceDetection(
  config: ClawGuardPluginConfig,
  workspacePath: string
): ClawGuardPluginConfig {
  if (!config.enclave.enabled) {
    return config;
  }
  
  const mergedFiles = mergeProtectedFiles(
    config.enclave.protectedFiles,
    workspacePath
  );
  
  return {
    ...config,
    enclave: {
      ...config.enclave,
      protectedFiles: mergedFiles,
    },
  };
}

/**
 * Expand ~ in paths
 */
export function expandPath(p: string): string {
  if (p.startsWith('~')) {
    return path.join(process.env.HOME || '', p.slice(1));
  }
  return p;
}
