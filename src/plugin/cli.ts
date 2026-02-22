/**
 * ClawGuard CLI - Plugin Registration
 * 
 * Provides CLI commands for ClawGuard that can be registered
 * with OpenClaw's plugin system or used standalone.
 */

import * as fs from 'fs';
import * as path from 'path';
import YAML from 'yaml';
import { 
  ClawGuardPluginConfig,
  DEFAULT_CONFIG,
  resolveConfig,
  detectWorkspaceFiles,
  applyWorkspaceDetection,
  expandPath,
} from './config';

// ============ Version ============
const VERSION = '0.1.0';

// ============ Colors & Formatting ============
const isTTY = process.stdout.isTTY;

const colors = {
  reset: isTTY ? '\x1b[0m' : '',
  bold: isTTY ? '\x1b[1m' : '',
  dim: isTTY ? '\x1b[2m' : '',
  red: isTTY ? '\x1b[31m' : '',
  green: isTTY ? '\x1b[32m' : '',
  yellow: isTTY ? '\x1b[33m' : '',
  blue: isTTY ? '\x1b[34m' : '',
  magenta: isTTY ? '\x1b[35m' : '',
  cyan: isTTY ? '\x1b[36m' : '',
  white: isTTY ? '\x1b[37m' : '',
  brightRed: isTTY ? '\x1b[91m' : '',
  brightGreen: isTTY ? '\x1b[92m' : '',
  brightYellow: isTTY ? '\x1b[93m' : '',
  brightBlue: isTTY ? '\x1b[94m' : '',
  brightMagenta: isTTY ? '\x1b[95m' : '',
  brightCyan: isTTY ? '\x1b[96m' : '',
};

const c = colors;

// ============ Config Management ============

const CONFIG_PATHS = [
  process.env.CLAWGUARD_CONFIG,
  './clawguard.yaml',
  './clawguard.yml',
  '~/.openclaw/clawguard.yaml',
  '~/.config/clawguard/config.yaml',
].filter(Boolean) as string[];

function findConfig(): string | null {
  for (const configPath of CONFIG_PATHS) {
    const expanded = expandPath(configPath);
    if (fs.existsSync(expanded)) {
      return expanded;
    }
  }
  return null;
}

function loadConfig(): ClawGuardPluginConfig {
  const configPath = findConfig();
  if (!configPath) {
    return DEFAULT_CONFIG;
  }
  
  try {
    const content = fs.readFileSync(configPath, 'utf-8');
    const rawConfig = YAML.parse(content);
    return resolveConfig(rawConfig);
  } catch {
    return DEFAULT_CONFIG;
  }
}

function saveConfig(config: ClawGuardPluginConfig): void {
  const configPath = findConfig() || expandPath('~/.openclaw/clawguard.yaml');
  const dir = path.dirname(configPath);
  
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  fs.writeFileSync(configPath, YAML.stringify(config));
  console.log(`Config saved to: ${configPath}`);
}

// ============ Banners ============

function getCompactBanner(): string {
  return `
${c.cyan}╔═══════════════════════════════════════════════════════════╗
║${c.reset}  ${c.brightMagenta}◢██◣${c.reset}  ${c.brightCyan}${c.bold}CLAWGUARD${c.reset} ${c.dim}— Security Layer for OpenClaw${c.reset}  ${c.dim}v${VERSION}${c.reset}  ${c.cyan}║
║${c.reset}  ${c.brightMagenta}█${c.white}💊${c.brightMagenta}█${c.reset}  ${c.dim}Protect your agents from prompt injection${c.reset}       ${c.cyan}║
║${c.reset}  ${c.brightMagenta}◥██◤${c.reset}                                                     ${c.cyan}║
╚═══════════════════════════════════════════════════════════╝${c.reset}
`;
}

// ============ Command Implementations ============

const SENSITIVITY_DESCRIPTIONS: Record<string, string> = {
  low: 'Flag only obvious attacks (fewer false positives)',
  medium: 'Balanced detection (recommended)',
  high: 'Aggressive scanning (may flag legitimate content)',
};

/**
 * Show current security status
 */
export function showStatus(): void {
  const config = loadConfig();
  const configPath = findConfig();
  const workspacePath = process.cwd();
  
  // Apply workspace detection
  const finalConfig = applyWorkspaceDetection(config, workspacePath);
  
  console.log(getCompactBanner());
  console.log(`${c.dim}Config:${c.reset} ${configPath || `${c.yellow}Using defaults${c.reset}`}\n`);
  
  const statusOn = `${c.brightGreen}✓ ACTIVE${c.reset}`;
  const statusOff = `${c.red}✗ DISABLED${c.reset}`;
  
  // Shield
  const shieldEnabled = finalConfig.shield.enabled;
  const sensitivity = finalConfig.shield.sensitivity;
  const sensitivityColor = sensitivity === 'high' ? c.red : sensitivity === 'medium' ? c.yellow : c.green;
  console.log(`${c.brightMagenta}InjectionShield${c.reset}  ${shieldEnabled ? statusOn : statusOff}`);
  if (shieldEnabled) {
    console.log(`  ${c.dim}├ Sensitivity:${c.reset} ${sensitivityColor}${sensitivity.toUpperCase()}${c.reset} ${c.dim}— ${SENSITIVITY_DESCRIPTIONS[sensitivity]}${c.reset}`);
  }
  
  // Scanner
  const scannerEnabled = finalConfig.scanner.enabled;
  console.log(`${c.brightMagenta}SecretScanner${c.reset}    ${scannerEnabled ? statusOn : statusOff}`);
  
  // Enclave
  const enclaveEnabled = finalConfig.enclave.enabled;
  console.log(`${c.brightMagenta}SecureEnclave${c.reset}    ${enclaveEnabled ? statusOn : statusOff}`);
  if (enclaveEnabled && finalConfig.enclave.protectedFiles.length) {
    const files = finalConfig.enclave.protectedFiles;
    console.log(`  ${c.dim}├ Protected:${c.reset} ${c.cyan}${files.slice(0, 5).join(`${c.reset}, ${c.cyan}`)}${c.reset}${files.length > 5 ? c.dim + ` +${files.length - 5} more` + c.reset : ''}`);
  }
  
  // Self-modification
  const selfModEnabled = finalConfig.selfModification.enabled;
  const requireApproval = finalConfig.selfModification.requireApproval;
  console.log(`${c.brightMagenta}SelfModGuard${c.reset}     ${selfModEnabled ? statusOn : statusOff}`);
  if (selfModEnabled) {
    console.log(`  ${c.dim}├ Mode:${c.reset} ${requireApproval ? `${c.yellow}Require approval${c.reset}` : `${c.red}Hard block${c.reset}`}`);
  }
  
  // Audit
  const auditEnabled = finalConfig.audit.enabled;
  console.log(`${c.brightMagenta}AuditLogger${c.reset}      ${auditEnabled ? statusOn : statusOff}`);
  if (auditEnabled && finalConfig.audit.logPath) {
    console.log(`  ${c.dim}├ Log:${c.reset} ${c.dim}${finalConfig.audit.logPath}${c.reset}`);
  }
  
  // Show auto-detected files
  const detectedFiles = detectWorkspaceFiles(workspacePath);
  if (detectedFiles.length > 0) {
    console.log(`\n${c.dim}Auto-detected workspace files:${c.reset}`);
    for (const file of detectedFiles) {
      console.log(`  ${c.brightCyan}↳${c.reset} ${file}`);
    }
  }
  
  console.log('');
}

/**
 * Show or set security level
 */
export function handleLevel(level?: string): void {
  if (level) {
    setLevel(level);
  } else {
    showLevel();
  }
}

function showLevel(): void {
  const config = loadConfig();
  const sensitivity = config.shield.sensitivity;
  const levelColors: Record<string, string> = { low: c.green, medium: c.yellow, high: c.red };
  
  console.log(`\n${c.bold}Current security level:${c.reset} ${levelColors[sensitivity]}${sensitivity.toUpperCase()}${c.reset}\n`);
  console.log(`${c.dim}Available levels:${c.reset}`);
  for (const [lvl, desc] of Object.entries(SENSITIVITY_DESCRIPTIONS)) {
    const marker = lvl === sensitivity ? `${c.brightCyan}▸${c.reset}` : ' ';
    const color = levelColors[lvl] || '';
    console.log(`  ${marker} ${color}${lvl.toUpperCase().padEnd(8)}${c.reset} ${c.dim}${desc}${c.reset}`);
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
  config.shield.sensitivity = normalized as 'low' | 'medium' | 'high';
  
  const levelColors: Record<string, string> = { low: c.green, medium: c.yellow, high: c.red };
  
  saveConfig(config);
  console.log(`\n${c.brightGreen}✓${c.reset} Security level set to: ${levelColors[normalized]}${normalized.toUpperCase()}${c.reset}`);
  console.log(`  ${c.dim}${SENSITIVITY_DESCRIPTIONS[normalized]}${c.reset}\n`);
}

/**
 * Scan a path for secrets
 */
export async function scanPath(targetPath: string): Promise<void> {
  const { SecretScanner } = await import('../scanner/secret-scanner');
  
  const fullPath = path.resolve(targetPath);
  
  if (!fs.existsSync(fullPath)) {
    console.error(`\n${c.red}❌ Path not found:${c.reset} ${fullPath}\n`);
    process.exit(1);
  }
  
  console.log(`\n${c.brightCyan}🔍 Scanning:${c.reset} ${fullPath}\n`);
  
  const scanner = new SecretScanner({});
  const stats = fs.statSync(fullPath);
  
  if (stats.isDirectory()) {
    const results = await scanner.scanDirectory(fullPath);
    let totalThreats = 0;
    
    for (const result of results) {
      if (result.threats.length > 0) {
        totalThreats += result.threats.length;
        console.log(`${c.yellow}⚠${c.reset}  ${c.dim}${result.filePath}${c.reset}`);
        for (const threat of result.threats) {
          console.log(`   ${c.red}↳${c.reset} ${threat.description} ${c.dim}(${threat.type})${c.reset}`);
        }
      }
    }
    
    if (totalThreats === 0) {
      console.log(`${c.brightGreen}✓${c.reset} No secrets detected in ${results.length} files\n`);
    } else {
      console.log(`\n${c.yellow}⚠${c.reset}  Found ${c.brightYellow}${totalThreats}${c.reset} potential secrets\n`);
    }
  } else {
    const content = fs.readFileSync(fullPath, 'utf-8');
    const result = scanner.scan(content);
    
    if (result.threats.length === 0) {
      console.log(`${c.brightGreen}✓${c.reset} No secrets detected\n`);
    } else {
      console.log(`${c.yellow}⚠${c.reset}  Found ${c.brightYellow}${result.threats.length}${c.reset} potential secrets:\n`);
      for (const threat of result.threats) {
        console.log(`   ${c.red}↳${c.reset} ${threat.description} ${c.dim}(${threat.type})${c.reset}`);
        if (threat.location) {
          console.log(`      ${c.dim}Line ${threat.location.line || '?'}${c.reset}`);
        }
      }
      console.log('');
    }
  }
}

/**
 * Show recent audit logs
 */
export async function showLogs(options?: { limit?: number }): Promise<void> {
  const config = loadConfig();
  const logPath = config.audit.logPath ? expandPath(config.audit.logPath) : expandPath('~/.openclaw/logs/clawguard.jsonl');
  
  if (!fs.existsSync(logPath)) {
    console.log(`\n${c.dim}No audit logs found at:${c.reset} ${logPath}\n`);
    return;
  }
  
  console.log(`\n${c.brightCyan}📋 Audit Logs${c.reset} ${c.dim}(${logPath})${c.reset}\n`);
  
  const limit = options?.limit || 20;
  
  try {
    const content = fs.readFileSync(logPath, 'utf-8');
    const lines = content.trim().split('\n').filter(Boolean);
    const recentLines = lines.slice(-limit);
    
    for (const line of recentLines) {
      try {
        const event = JSON.parse(line);
        const timestamp = new Date(event.timestamp).toLocaleString();
        const eventType = event.eventType || 'unknown';
        
        let icon = '•';
        let color = c.dim;
        
        switch (eventType) {
          case 'threat_detected':
            icon = '⚠';
            color = c.yellow;
            break;
          case 'tool_invocation':
            icon = '🔧';
            color = c.cyan;
            break;
          case 'enclave_request':
          case 'enclave_decision':
            icon = '🔒';
            color = c.magenta;
            break;
          case 'secret_detected':
            icon = '🔑';
            color = c.red;
            break;
          case 'config_change':
            icon = '⚙';
            color = c.blue;
            break;
        }
        
        console.log(`${c.dim}${timestamp}${c.reset} ${icon} ${color}${eventType}${c.reset}`);
        
        // Show relevant data
        if (event.data) {
          if (event.data.tool) {
            console.log(`  ${c.dim}Tool:${c.reset} ${event.data.tool}`);
          }
          if (event.data.threats && event.data.threats.length > 0) {
            console.log(`  ${c.dim}Threats:${c.reset} ${event.data.threats.map((t: { type: string }) => t.type).join(', ')}`);
          }
          if (event.data.action) {
            console.log(`  ${c.dim}Action:${c.reset} ${event.data.action}`);
          }
        }
      } catch {
        // Skip malformed lines
      }
    }
    
    if (lines.length > limit) {
      console.log(`\n${c.dim}Showing last ${limit} of ${lines.length} entries${c.reset}`);
    }
  } catch (error) {
    console.error(`\n${c.red}❌ Error reading logs:${c.reset} ${error}\n`);
  }
  
  console.log('');
}

/**
 * Enable/disable a component
 */
export function toggleComponent(component: string, enable: boolean): void {
  const config = loadConfig();
  const comp = component.toLowerCase();
  
  const componentMap: Record<string, keyof ClawGuardPluginConfig> = {
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
  
  (config[configKey] as { enabled: boolean }).enabled = enable;
  
  saveConfig(config);
  
  if (enable) {
    console.log(`\n${c.brightGreen}✓${c.reset} ${c.brightMagenta}${component}${c.reset} ${c.green}enabled${c.reset}\n`);
  } else {
    console.log(`\n${c.yellow}⚠${c.reset}  ${c.brightMagenta}${component}${c.reset} ${c.red}disabled${c.reset}\n`);
  }
}

// ============ Plugin CLI Registration ============

/**
 * PluginApi interface (subset for CLI registration)
 */
export interface PluginCliContext {
  program: {
    command: (name: string) => PluginCommand;
  };
}

interface PluginCommand {
  description: (desc: string) => PluginCommand;
  command: (name: string) => PluginCommand;
  argument: (name: string, desc?: string) => PluginCommand;
  option: (flags: string, desc?: string, defaultValue?: string) => PluginCommand;
  action: (fn: (...args: any[]) => void | Promise<void>) => PluginCommand;
}

/**
 * Register ClawGuard CLI commands with OpenClaw plugin system
 */
export function registerCli(api: { registerCli?: (handler: (ctx: PluginCliContext) => void) => void }): void {
  if (!api.registerCli) {
    return;
  }
  
  api.registerCli(({ program }) => {
    const cmd = program.command('clawguard').description('ClawGuard security tools');
    
    cmd.command('status')
      .description('Show current security status')
      .action(() => showStatus());
    
    cmd.command('level')
      .argument('[level]', 'Security level (low/medium/high)')
      .description('Show or set security level')
      .action((level: any) => handleLevel(level));
    
    cmd.command('scan')
      .argument('<path>', 'Path to scan')
      .description('Scan path for secrets')
      .action((p: any) => scanPath(p));
    
    cmd.command('logs')
      .option('-n, --limit <number>', 'Number of entries to show')
      .description('Show recent audit logs')
      .action((opts: any) => {
        const limit = opts?.limit ? parseInt(opts.limit, 10) : undefined;
        showLogs({ limit });
      });
    
    cmd.command('enable')
      .argument('<component>', 'Component to enable')
      .description('Enable a security component')
      .action((component: any) => toggleComponent(component, true));
    
    cmd.command('disable')
      .argument('<component>', 'Component to disable')
      .description('Disable a security component')
      .action((component: any) => toggleComponent(component, false));
  });
}

// ============ Exports ============

export {
  loadConfig,
  saveConfig,
  findConfig,
  VERSION,
  colors,
};
