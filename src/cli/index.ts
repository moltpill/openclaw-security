#!/usr/bin/env node
/**
 * ClawGuard CLI
 * 
 * Manage security levels and view status from the command line.
 */

import * as fs from 'fs';
import * as path from 'path';
import YAML from 'yaml';

// ============ Version ============
const VERSION = '0.1.0';

// ============ Colors & Formatting ============
const isTTY = process.stdout.isTTY;

const colors = {
  reset: isTTY ? '\x1b[0m' : '',
  bold: isTTY ? '\x1b[1m' : '',
  dim: isTTY ? '\x1b[2m' : '',
  
  // Foreground
  red: isTTY ? '\x1b[31m' : '',
  green: isTTY ? '\x1b[32m' : '',
  yellow: isTTY ? '\x1b[33m' : '',
  blue: isTTY ? '\x1b[34m' : '',
  magenta: isTTY ? '\x1b[35m' : '',
  cyan: isTTY ? '\x1b[36m' : '',
  white: isTTY ? '\x1b[37m' : '',
  
  // Bright
  brightRed: isTTY ? '\x1b[91m' : '',
  brightGreen: isTTY ? '\x1b[92m' : '',
  brightYellow: isTTY ? '\x1b[93m' : '',
  brightBlue: isTTY ? '\x1b[94m' : '',
  brightMagenta: isTTY ? '\x1b[95m' : '',
  brightCyan: isTTY ? '\x1b[96m' : '',
};

const c = colors;

// ============ ASCII Art Banner ============
function getBanner(): string {
  // Cyberpunk pharmacy shield - Matrix meets medical precision
  return `
${c.cyan}    ╔═══════════════════════════════════════════════════════════════╗
    ║${c.reset}                                                                 ${c.cyan}║
    ║${c.brightCyan}       ██████╗██╗      █████╗ ██╗    ██╗ ██████╗ ██╗   ██╗${c.cyan}       ║
    ║${c.brightCyan}      ██╔════╝██║     ██╔══██╗██║    ██║██╔════╝ ██║   ██║${c.cyan}       ║
    ║${c.brightCyan}      ██║     ██║     ███████║██║ █╗ ██║██║  ███╗██║   ██║${c.cyan}       ║
    ║${c.brightCyan}      ██║     ██║     ██╔══██║██║███╗██║██║   ██║██║   ██║${c.cyan}       ║
    ║${c.brightCyan}      ╚██████╗███████╗██║  ██║╚███╔███╔╝╚██████╔╝╚██████╔╝${c.cyan}       ║
    ║${c.brightCyan}       ╚═════╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝  ╚═════╝  ╚═════╝${c.cyan}        ║
    ║${c.reset}                                                                 ${c.cyan}║
    ║${c.reset}     ${c.brightMagenta}╭─────────────╮${c.reset}      ${c.brightGreen}┏━━━━━━━━━━━━━━━━━━━━━━━━━┓${c.reset}     ${c.cyan}║
    ║${c.reset}     ${c.brightMagenta}│  ◢██████◣  │${c.reset}      ${c.brightGreen}┃${c.reset}   ${c.bold}${c.white}SECURITY LAYER FOR${c.reset}     ${c.brightGreen}┃${c.reset}     ${c.cyan}║
    ║${c.reset}     ${c.brightMagenta}│ ███${c.white}💊${c.brightMagenta}███ │${c.reset}      ${c.brightGreen}┃${c.reset}   ${c.bold}${c.white}OPENCLAW AGENTS${c.reset}        ${c.brightGreen}┃${c.reset}     ${c.cyan}║
    ║${c.reset}     ${c.brightMagenta}│  ◥██████◤  │${c.reset}      ${c.brightGreen}┗━━━━━━━━━━━━━━━━━━━━━━━━━┛${c.reset}     ${c.cyan}║
    ║${c.reset}     ${c.brightMagenta}│  ◥██████◤  │${c.reset}                                    ${c.cyan}║
    ║${c.reset}     ${c.brightMagenta}│   ◥████◤   │${c.reset}      ${c.dim}Protect • Detect • Audit${c.reset}       ${c.cyan}║
    ║${c.reset}     ${c.brightMagenta}╰─────────────╯${c.reset}                                    ${c.cyan}║
    ║${c.reset}                                                                 ${c.cyan}║
    ║${c.reset}     ${c.dim}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${c.reset}     ${c.cyan}║
    ║${c.reset}     ${c.brightYellow}⚡${c.reset} ${c.bold}MoltPill Security${c.reset}                     ${c.dim}v${VERSION}${c.reset}     ${c.cyan}║
    ╚═══════════════════════════════════════════════════════════════╝${c.reset}
`;
}

// Compact banner for status command
function getCompactBanner(): string {
  return `
${c.cyan}╔═══════════════════════════════════════════════════════════╗
║${c.reset}  ${c.brightMagenta}◢██◣${c.reset}  ${c.brightCyan}${c.bold}CLAWGUARD${c.reset} ${c.dim}— Security Layer for OpenClaw${c.reset}  ${c.dim}v${VERSION}${c.reset}  ${c.cyan}║
║${c.reset}  ${c.brightMagenta}█${c.white}💊${c.brightMagenta}█${c.reset}  ${c.dim}Protect your agents from prompt injection${c.reset}       ${c.cyan}║
║${c.reset}  ${c.brightMagenta}◥██◤${c.reset}                                                     ${c.cyan}║
╚═══════════════════════════════════════════════════════════╝${c.reset}
`;
}

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
  
  console.log(getCompactBanner());
  console.log(`${c.dim}Config:${c.reset} ${configPath || `${c.yellow}Using defaults${c.reset}`}\n`);
  
  const statusOn = `${c.brightGreen}✓ ACTIVE${c.reset}`;
  const statusOff = `${c.red}✗ DISABLED${c.reset}`;
  
  // Shield
  const shieldEnabled = config.shield?.enabled !== false;
  const sensitivity = config.shield?.sensitivity || 'medium';
  const sensitivityColor = sensitivity === 'high' ? c.red : sensitivity === 'medium' ? c.yellow : c.green;
  console.log(`${c.brightMagenta}InjectionShield${c.reset}  ${shieldEnabled ? statusOn : statusOff}`);
  if (shieldEnabled) {
    console.log(`  ${c.dim}├ Sensitivity:${c.reset} ${sensitivityColor}${sensitivity.toUpperCase()}${c.reset} ${c.dim}— ${SENSITIVITY_DESCRIPTIONS[sensitivity]}${c.reset}`);
  }
  
  // Scanner
  const scannerEnabled = config.scanner?.enabled !== false;
  console.log(`${c.brightMagenta}SecretScanner${c.reset}    ${scannerEnabled ? statusOn : statusOff}`);
  
  // Enclave
  const enclaveEnabled = config.enclave?.enabled !== false;
  console.log(`${c.brightMagenta}SecureEnclave${c.reset}    ${enclaveEnabled ? statusOn : statusOff}`);
  if (enclaveEnabled && config.enclave?.protectedFiles?.length) {
    console.log(`  ${c.dim}├ Protected:${c.reset} ${c.cyan}${config.enclave.protectedFiles.join(`${c.reset}, ${c.cyan}`)}${c.reset}`);
  }
  
  // Self-modification
  const selfModEnabled = config.selfModification?.enabled !== false;
  const requireApproval = config.selfModification?.requireApproval !== false;
  console.log(`${c.brightMagenta}SelfModGuard${c.reset}     ${selfModEnabled ? statusOn : statusOff}`);
  if (selfModEnabled) {
    console.log(`  ${c.dim}├ Mode:${c.reset} ${requireApproval ? `${c.yellow}Require approval${c.reset}` : `${c.red}Hard block${c.reset}`}`);
  }
  
  // Audit
  const auditEnabled = config.audit?.enabled !== false;
  console.log(`${c.brightMagenta}AuditLogger${c.reset}      ${auditEnabled ? statusOn : statusOff}`);
  if (auditEnabled && config.audit?.logPath) {
    console.log(`  ${c.dim}├ Log:${c.reset} ${c.dim}${config.audit.logPath}${c.reset}`);
  }
  
  console.log('');
}

function showLevel(): void {
  const config = loadConfig();
  const sensitivity = config.shield?.sensitivity || 'medium';
  const levelColors: Record<string, string> = { low: c.green, medium: c.yellow, high: c.red };
  
  console.log(`\n${c.bold}Current security level:${c.reset} ${levelColors[sensitivity]}${sensitivity.toUpperCase()}${c.reset}\n`);
  console.log(`${c.dim}Available levels:${c.reset}`);
  for (const [level, desc] of Object.entries(SENSITIVITY_DESCRIPTIONS)) {
    const marker = level === sensitivity ? `${c.brightCyan}▸${c.reset}` : ' ';
    const color = levelColors[level] || '';
    console.log(`  ${marker} ${color}${level.toUpperCase().padEnd(8)}${c.reset} ${c.dim}${desc}${c.reset}`);
  }
  console.log('');
}

function setLevel(level: string): void {
  const normalized = level.toLowerCase();
  
  if (!['low', 'medium', 'high'].includes(normalized)) {
    console.error(`\n${c.red}❌ Invalid level:${c.reset} ${level}`);
    console.error(`   ${c.dim}Valid levels: low, medium, high${c.reset}\n`);
    process.exit(1);
  }
  
  const config = loadConfig();
  config.shield = config.shield || {};
  config.shield.sensitivity = normalized as 'low' | 'medium' | 'high';
  
  const levelColors: Record<string, string> = { low: c.green, medium: c.yellow, high: c.red };
  
  saveConfig(config);
  console.log(`\n${c.brightGreen}✓${c.reset} Security level set to: ${levelColors[normalized]}${normalized.toUpperCase()}${c.reset}`);
  console.log(`  ${c.dim}${SENSITIVITY_DESCRIPTIONS[normalized as keyof typeof SENSITIVITY_DESCRIPTIONS]}${c.reset}\n`);
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
    console.error(`\n${c.red}❌ Unknown component:${c.reset} ${component}`);
    console.error(`   ${c.dim}Valid components: shield, scanner, enclave, selfmod, audit${c.reset}\n`);
    process.exit(1);
  }
  
  (config[configKey] as any) = (config[configKey] as any) || {};
  (config[configKey] as any).enabled = true;
  
  saveConfig(config);
  console.log(`\n${c.brightGreen}✓${c.reset} ${c.brightMagenta}${component}${c.reset} ${c.green}enabled${c.reset}\n`);
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
    console.error(`\n${c.red}❌ Unknown component:${c.reset} ${component}`);
    console.error(`   ${c.dim}Valid components: shield, scanner, enclave, selfmod, audit${c.reset}\n`);
    process.exit(1);
  }
  
  (config[configKey] as any) = (config[configKey] as any) || {};
  (config[configKey] as any).enabled = false;
  
  saveConfig(config);
  console.log(`\n${c.yellow}⚠${c.reset}  ${c.brightMagenta}${component}${c.reset} ${c.red}disabled${c.reset}\n`);
}

function showHelp(): void {
  console.log(getBanner());
  
  console.log(`
${c.bold}${c.white}USAGE${c.reset}
    ${c.cyan}clawguard${c.reset} ${c.dim}<command>${c.reset} ${c.dim}[options]${c.reset}

${c.bold}${c.white}COMMANDS${c.reset}
    ${c.brightGreen}status${c.reset}              Show current security status and config
    ${c.brightGreen}level${c.reset}               Display current security level
    ${c.brightGreen}level${c.reset} ${c.yellow}<low|med|hi>${c.reset}  Set shield sensitivity level
    ${c.brightGreen}enable${c.reset} ${c.yellow}<component>${c.reset}  Enable a security component
    ${c.brightGreen}disable${c.reset} ${c.yellow}<component>${c.reset} Disable a security component
    ${c.brightGreen}init${c.reset}                Create default config file
    ${c.brightGreen}help${c.reset}                Show this help message
    ${c.brightGreen}--version, -v${c.reset}       Show version number

${c.bold}${c.white}COMPONENTS${c.reset}
    ${c.brightMagenta}shield${c.reset}    ${c.dim}│${c.reset} InjectionShield  ${c.dim}— Detects prompt injection attacks${c.reset}
    ${c.brightMagenta}scanner${c.reset}   ${c.dim}│${c.reset} SecretScanner    ${c.dim}— Prevents secret/credential leaks${c.reset}
    ${c.brightMagenta}enclave${c.reset}   ${c.dim}│${c.reset} SecureEnclave    ${c.dim}— Protects sensitive files from access${c.reset}
    ${c.brightMagenta}selfmod${c.reset}   ${c.dim}│${c.reset} SelfModGuard     ${c.dim}— Blocks unauthorized self-modification${c.reset}
    ${c.brightMagenta}audit${c.reset}     ${c.dim}│${c.reset} AuditLogger      ${c.dim}— Logs all security events${c.reset}

${c.bold}${c.white}SECURITY LEVELS${c.reset}
    ${c.green}LOW${c.reset}       Flag only obvious attacks ${c.dim}(fewer false positives)${c.reset}
    ${c.yellow}MEDIUM${c.reset}    Balanced detection ${c.dim}(recommended)${c.reset}
    ${c.red}HIGH${c.reset}      Aggressive scanning ${c.dim}(maximum security, more flags)${c.reset}

${c.bold}${c.white}EXAMPLES${c.reset}
    ${c.dim}# View current security status${c.reset}
    ${c.cyan}$${c.reset} clawguard status

    ${c.dim}# Set aggressive security mode${c.reset}
    ${c.cyan}$${c.reset} clawguard level high

    ${c.dim}# Disable secret scanning${c.reset}
    ${c.cyan}$${c.reset} clawguard disable scanner

    ${c.dim}# Create config with defaults${c.reset}
    ${c.cyan}$${c.reset} clawguard init

${c.bold}${c.white}CONFIG LOCATIONS${c.reset} ${c.dim}(in priority order)${c.reset}
    ${c.yellow}1.${c.reset} ${c.dim}$CLAWGUARD_CONFIG${c.reset}          ${c.dim}— Environment override${c.reset}
    ${c.yellow}2.${c.reset} ./clawguard.yaml          ${c.dim}— Project-local${c.reset}
    ${c.yellow}3.${c.reset} ~/.openclaw/clawguard.yaml ${c.dim}— User default${c.reset}
    ${c.yellow}4.${c.reset} ~/.config/clawguard/config.yaml

${c.bold}${c.white}LINKS${c.reset}
    ${c.brightCyan}📖 Documentation:${c.reset}  https://github.com/moltpill/clawguard#readme
    ${c.brightCyan}🐛 Issues:${c.reset}         https://github.com/moltpill/clawguard/issues
    ${c.brightCyan}📦 npm:${c.reset}            https://npmjs.com/package/@moltpill/clawguard

${c.dim}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${c.reset}
${c.brightMagenta}💊${c.reset} ${c.bold}MoltPill${c.reset} ${c.dim}— Protecting AI agents, one injection at a time.${c.reset}
`);
}

function showVersion(): void {
  console.log(`${c.brightCyan}clawguard${c.reset} ${c.dim}v${c.reset}${VERSION}`);
}

function initConfig(): void {
  const configPath = expandPath('~/.openclaw/clawguard.yaml');
  
  if (fs.existsSync(configPath)) {
    console.log(`\n${c.yellow}⚠${c.reset}  Config already exists: ${c.cyan}${configPath}${c.reset}`);
    console.log(`   ${c.dim}Use "clawguard status" to view current settings${c.reset}\n`);
    return;
  }
  
  const config = getDefaultConfig();
  saveConfig(config);
  
  console.log(`\n${c.brightGreen}✓${c.reset} ${c.bold}Created default config with:${c.reset}`);
  console.log(`   ${c.dim}•${c.reset} Shield: ${c.yellow}MEDIUM${c.reset} sensitivity`);
  console.log(`   ${c.dim}•${c.reset} Scanner: ${c.green}Enabled${c.reset}`);
  console.log(`   ${c.dim}•${c.reset} Enclave: ${c.cyan}SOUL.md, USER.md, secrets/*${c.reset}`);
  console.log(`   ${c.dim}•${c.reset} SelfMod: ${c.yellow}Require approval${c.reset}`);
  console.log(`   ${c.dim}•${c.reset} Audit: ${c.green}Enabled${c.reset}\n`);
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
        console.error(`\n${c.red}❌ Usage:${c.reset} clawguard enable <component>\n`);
        process.exit(1);
      }
      enableComponent(args[1]);
      break;
    case 'disable':
      if (!args[1]) {
        console.error(`\n${c.red}❌ Usage:${c.reset} clawguard disable <component>\n`);
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
    case '--version':
    case '-v':
    case 'version':
      showVersion();
      break;
    case undefined:
      showStatus();
      break;
    default:
      console.error(`\n${c.red}❌ Unknown command:${c.reset} ${command}`);
      showHelp();
      process.exit(1);
  }
}

main();
