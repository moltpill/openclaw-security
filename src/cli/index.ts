#!/usr/bin/env node
/**
 * ClawGuard CLI
 * 
 * Manage security levels and view status from the command line.
 */

import * as fs from 'fs';
import * as path from 'path';
import YAML from 'yaml';

const CONFIG_PATHS = [
  process.env.CLAWGUARD_CONFIG,
  './clawguard.yaml',
  './clawguard.yml',
  '~/.openclaw/clawguard.yaml',
  '~/.config/clawguard/config.yaml',
].filter(Boolean) as string[];

interface ClawGuardConfig {
  shield?: {
    enabled?: boolean;
    sensitivity?: 'low' | 'medium' | 'high';
  };
  scanner?: {
    enabled?: boolean;
  };
  enclave?: {
    enabled?: boolean;
    protectedFiles?: string[];
  };
  selfModification?: {
    enabled?: boolean;
    requireApproval?: boolean;
  };
  audit?: {
    enabled?: boolean;
    logPath?: string;
  };
}

function expandPath(p: string): string {
  if (p.startsWith('~')) {
    return path.join(process.env.HOME || '', p.slice(1));
  }
  return p;
}

function findConfig(): string | null {
  for (const configPath of CONFIG_PATHS) {
    const expanded = expandPath(configPath);
    if (fs.existsSync(expanded)) {
      return expanded;
    }
  }
  return null;
}

function loadConfig(): ClawGuardConfig {
  const configPath = findConfig();
  if (!configPath) {
    return getDefaultConfig();
  }
  
  try {
    const content = fs.readFileSync(configPath, 'utf-8');
    return YAML.parse(content) || getDefaultConfig();
  } catch {
    return getDefaultConfig();
  }
}

function saveConfig(config: ClawGuardConfig): void {
  const configPath = findConfig() || expandPath('~/.openclaw/clawguard.yaml');
  const dir = path.dirname(configPath);
  
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  fs.writeFileSync(configPath, YAML.stringify(config));
  console.log(`Config saved to: ${configPath}`);
}

function getDefaultConfig(): ClawGuardConfig {
  return {
    shield: { enabled: true, sensitivity: 'medium' },
    scanner: { enabled: true },
    enclave: { enabled: true, protectedFiles: ['SOUL.md', 'USER.md', 'secrets/*'] },
    selfModification: { enabled: true, requireApproval: true },
    audit: { enabled: true, logPath: '~/.openclaw/logs/clawguard.jsonl' },
  };
}

const SENSITIVITY_DESCRIPTIONS = {
  low: 'Flag only obvious attacks (fewer false positives)',
  medium: 'Balanced detection (recommended)',
  high: 'Aggressive scanning (may flag legitimate content)',
};

// ============ Commands ============

function showStatus(): void {
  const config = loadConfig();
  const configPath = findConfig();
  
  console.log('\n🛡️  ClawGuard Status\n');
  console.log(`Config: ${configPath || 'Using defaults'}\n`);
  
  // Shield
  const shieldEnabled = config.shield?.enabled !== false;
  const sensitivity = config.shield?.sensitivity || 'medium';
  console.log(`InjectionShield: ${shieldEnabled ? '✅ Active' : '❌ Disabled'}`);
  if (shieldEnabled) {
    console.log(`  Sensitivity: ${sensitivity.toUpperCase()} — ${SENSITIVITY_DESCRIPTIONS[sensitivity]}`);
  }
  
  // Scanner
  const scannerEnabled = config.scanner?.enabled !== false;
  console.log(`SecretScanner:   ${scannerEnabled ? '✅ Active' : '❌ Disabled'}`);
  
  // Enclave
  const enclaveEnabled = config.enclave?.enabled !== false;
  console.log(`SecureEnclave:   ${enclaveEnabled ? '✅ Active' : '❌ Disabled'}`);
  if (enclaveEnabled && config.enclave?.protectedFiles?.length) {
    console.log(`  Protected: ${config.enclave.protectedFiles.join(', ')}`);
  }
  
  // Self-modification
  const selfModEnabled = config.selfModification?.enabled !== false;
  const requireApproval = config.selfModification?.requireApproval !== false;
  console.log(`SelfModGuard:    ${selfModEnabled ? '✅ Active' : '❌ Disabled'}`);
  if (selfModEnabled) {
    console.log(`  Mode: ${requireApproval ? 'Require approval' : 'Hard block'}`);
  }
  
  // Audit
  const auditEnabled = config.audit?.enabled !== false;
  console.log(`AuditLogger:     ${auditEnabled ? '✅ Active' : '❌ Disabled'}`);
  if (auditEnabled && config.audit?.logPath) {
    console.log(`  Log: ${config.audit.logPath}`);
  }
  
  console.log('');
}

function showLevel(): void {
  const config = loadConfig();
  const sensitivity = config.shield?.sensitivity || 'medium';
  
  console.log(`\nCurrent security level: ${sensitivity.toUpperCase()}\n`);
  console.log('Available levels:');
  for (const [level, desc] of Object.entries(SENSITIVITY_DESCRIPTIONS)) {
    const marker = level === sensitivity ? '→' : ' ';
    console.log(`  ${marker} ${level.toUpperCase().padEnd(8)} ${desc}`);
  }
  console.log('');
}

function setLevel(level: string): void {
  const normalized = level.toLowerCase();
  
  if (!['low', 'medium', 'high'].includes(normalized)) {
    console.error(`\n❌ Invalid level: ${level}`);
    console.error('   Valid levels: low, medium, high\n');
    process.exit(1);
  }
  
  const config = loadConfig();
  config.shield = config.shield || {};
  config.shield.sensitivity = normalized as 'low' | 'medium' | 'high';
  
  saveConfig(config);
  console.log(`\n✅ Security level set to: ${normalized.toUpperCase()}`);
  console.log(`   ${SENSITIVITY_DESCRIPTIONS[normalized as keyof typeof SENSITIVITY_DESCRIPTIONS]}\n`);
}

function enableComponent(component: string): void {
  const config = loadConfig();
  const comp = component.toLowerCase();
  
  const componentMap: Record<string, keyof ClawGuardConfig> = {
    shield: 'shield',
    scanner: 'scanner',
    enclave: 'enclave',
    selfmod: 'selfModification',
    audit: 'audit',
  };
  
  const configKey = componentMap[comp];
  if (!configKey) {
    console.error(`\n❌ Unknown component: ${component}`);
    console.error('   Valid components: shield, scanner, enclave, selfmod, audit\n');
    process.exit(1);
  }
  
  (config[configKey] as any) = (config[configKey] as any) || {};
  (config[configKey] as any).enabled = true;
  
  saveConfig(config);
  console.log(`\n✅ ${component} enabled\n`);
}

function disableComponent(component: string): void {
  const config = loadConfig();
  const comp = component.toLowerCase();
  
  const componentMap: Record<string, keyof ClawGuardConfig> = {
    shield: 'shield',
    scanner: 'scanner',
    enclave: 'enclave',
    selfmod: 'selfModification',
    audit: 'audit',
  };
  
  const configKey = componentMap[comp];
  if (!configKey) {
    console.error(`\n❌ Unknown component: ${component}`);
    console.error('   Valid components: shield, scanner, enclave, selfmod, audit\n');
    process.exit(1);
  }
  
  (config[configKey] as any) = (config[configKey] as any) || {};
  (config[configKey] as any).enabled = false;
  
  saveConfig(config);
  console.log(`\n⚠️  ${component} disabled\n`);
}

function showHelp(): void {
  console.log(`
🛡️  ClawGuard CLI — Security for OpenClaw Agents

Usage: clawguard <command> [options]

Commands:
  status              Show current security status
  level               Show current security level
  level <low|med|hi>  Set security level (shield sensitivity)
  enable <component>  Enable a security component
  disable <component> Disable a security component
  init                Create default config file
  help                Show this help message

Components:
  shield    Injection detection (InjectionShield)
  scanner   Secret scanning (SecretScanner)
  enclave   Protected files (SecureEnclave)
  selfmod   Self-modification guard (SelfModificationGuard)
  audit     Activity logging (AuditLogger)

Examples:
  clawguard status           # View all component status
  clawguard level high       # Set to aggressive scanning
  clawguard disable scanner  # Turn off secret scanning
  clawguard enable selfmod   # Turn on self-mod protection

Config locations (in order):
  $CLAWGUARD_CONFIG
  ./clawguard.yaml
  ~/.openclaw/clawguard.yaml
  ~/.config/clawguard/config.yaml
`);
}

function initConfig(): void {
  const configPath = expandPath('~/.openclaw/clawguard.yaml');
  
  if (fs.existsSync(configPath)) {
    console.log(`\n⚠️  Config already exists: ${configPath}`);
    console.log('   Use "clawguard status" to view current settings\n');
    return;
  }
  
  const config = getDefaultConfig();
  saveConfig(config);
  
  console.log('\n✅ Created default config with:');
  console.log('   • Shield: MEDIUM sensitivity');
  console.log('   • Scanner: Enabled');
  console.log('   • Enclave: SOUL.md, USER.md, secrets/*');
  console.log('   • SelfMod: Require approval');
  console.log('   • Audit: Enabled\n');
}

// ============ Main ============

function main(): void {
  const args = process.argv.slice(2);
  const command = args[0]?.toLowerCase();
  
  switch (command) {
    case 'status':
      showStatus();
      break;
    case 'level':
      if (args[1]) {
        setLevel(args[1]);
      } else {
        showLevel();
      }
      break;
    case 'enable':
      if (!args[1]) {
        console.error('\n❌ Usage: clawguard enable <component>\n');
        process.exit(1);
      }
      enableComponent(args[1]);
      break;
    case 'disable':
      if (!args[1]) {
        console.error('\n❌ Usage: clawguard disable <component>\n');
        process.exit(1);
      }
      disableComponent(args[1]);
      break;
    case 'init':
      initConfig();
      break;
    case 'help':
    case '--help':
    case '-h':
      showHelp();
      break;
    case undefined:
      showStatus();
      break;
    default:
      console.error(`\n❌ Unknown command: ${command}`);
      showHelp();
      process.exit(1);
  }
}

main();
