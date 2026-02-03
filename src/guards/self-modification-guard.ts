/**
 * SelfModificationGuard - Prevents agents from modifying their own installation
 * 
 * Critical for preventing runaway self-update loops where an agent:
 * 1. Decides to update itself while debugging
 * 2. Gets killed mid-install (SIGTERM)
 * 3. Finds itself broken and tries to "fix" it
 * 4. Makes things worse until OOM death spiral
 */

export interface SelfModificationPolicy {
  enabled: boolean;
  blockInstall: boolean;      // npm/pip/brew install openclaw*
  blockUninstall: boolean;    // rm -rf */openclaw*
  blockGatewayControl: boolean; // openclaw gateway restart/stop
  blockConfigEdit: boolean;   // writes to openclaw config files
  blockProcessKill: boolean;  // kill/pkill gateway process
  requireApproval: boolean;   // allow with human approval vs hard block
  customPatterns?: string[];  // additional patterns to block
}

export interface SelfModificationCheckResult {
  blocked: boolean;
  requiresApproval: boolean;
  reason: string;
  category: SelfModificationCategory;
  matchedPattern?: string;
}

export type SelfModificationCategory = 
  | 'allowed'
  | 'package-install'
  | 'package-uninstall'
  | 'gateway-control'
  | 'config-edit'
  | 'process-kill'
  | 'custom';

// Built-in patterns for each category
const PATTERNS: Record<Exclude<SelfModificationCategory, 'allowed' | 'custom'>, RegExp[]> = {
  'package-install': [
    // npm
    /npm\s+(i|install|add|update)\s+.*openclaw/i,
    /npm\s+(i|install|add|update)\s+-g\s+.*openclaw/i,
    /npm\s+(i|install|add|update)\s+--global\s+.*openclaw/i,
    // pnpm
    /pnpm\s+(i|install|add|update)\s+.*openclaw/i,
    /pnpm\s+(i|install|add|update)\s+-g\s+.*openclaw/i,
    // yarn
    /yarn\s+(add|upgrade)\s+.*openclaw/i,
    /yarn\s+global\s+add\s+.*openclaw/i,
    // pip
    /pip3?\s+install\s+.*openclaw/i,
    // brew
    /brew\s+(install|upgrade|reinstall)\s+.*openclaw/i,
  ],
  'package-uninstall': [
    // npm uninstall
    /npm\s+(un|uninstall|remove|rm)\s+.*openclaw/i,
    /pnpm\s+(un|uninstall|remove|rm)\s+.*openclaw/i,
    /yarn\s+(remove)\s+.*openclaw/i,
    // rm operations on openclaw directories
    /rm\s+(-rf?|--recursive)?\s+.*node_modules.*openclaw/i,
    /rm\s+(-rf?|--recursive)?\s+.*lib\/node_modules.*openclaw/i,
    /rm\s+(-rf?|--recursive)?\s+.*\.openclaw/i,
    /rm\s+.*\/bin\/openclaw/i,
    // pip uninstall
    /pip3?\s+uninstall\s+.*openclaw/i,
    // brew uninstall
    /brew\s+(uninstall|remove|rm)\s+.*openclaw/i,
  ],
  'gateway-control': [
    /openclaw\s+gateway\s+(restart|stop|start)/i,
    /openclaw\s+update/i,
    /openclaw\s+self-update/i,
    /openclaw\s+upgrade/i,
    // Direct service control
    /systemctl\s+(restart|stop|start)\s+.*openclaw/i,
    /launchctl\s+(stop|unload|kickstart)\s+.*openclaw/i,
    /service\s+openclaw\s+(restart|stop|start)/i,
  ],
  'config-edit': [
    // Direct writes to config files
    />\s*.*openclaw.*\.(yaml|yml|json|config)/i,
    /tee\s+.*openclaw.*\.(yaml|yml|json|config)/i,
    />\s*.*\.openclaw\/config/i,
    />\s*.*\.openclaw\/gateway/i,
    // Editors on config files (might be too aggressive)
    // /vi(m)?\s+.*\.openclaw\//i,
    // /nano\s+.*\.openclaw\//i,
  ],
  'process-kill': [
    /kill\s+(-9\s+)?.*gateway/i,
    /pkill\s+(-9\s+)?.*openclaw/i,
    /pkill\s+(-9\s+)?.*gateway/i,
    /killall\s+.*openclaw/i,
    /killall\s+.*gateway/i,
    // Kill by PID file
    /kill\s+.*\$\(cat.*openclaw.*\.pid\)/i,
  ],
};

export class SelfModificationGuard {
  private policy: SelfModificationPolicy;
  private customPatterns: RegExp[] = [];

  constructor(policy?: Partial<SelfModificationPolicy>) {
    this.policy = {
      enabled: true,
      blockInstall: true,
      blockUninstall: true,
      blockGatewayControl: true,
      blockConfigEdit: true,
      blockProcessKill: true,
      requireApproval: true,
      ...policy,
    };

    // Compile custom patterns
    if (policy?.customPatterns) {
      this.customPatterns = policy.customPatterns.map(p => {
        // Convert glob-like patterns to regex
        const regexStr = p
          .replace(/\*/g, '.*')
          .replace(/\?/g, '.');
        return new RegExp(regexStr, 'i');
      });
    }
  }

  /**
   * Check if a command would modify the agent's own installation
   */
  check(command: string): SelfModificationCheckResult {
    if (!this.policy.enabled) {
      return {
        blocked: false,
        requiresApproval: false,
        reason: 'Self-modification guard disabled',
        category: 'allowed',
      };
    }

    // Normalize command
    const normalizedCommand = command.trim();

    // Check each category
    if (this.policy.blockInstall) {
      const match = this.matchCategory('package-install', normalizedCommand);
      if (match) {
        return this.buildResult('package-install', match, 
          'Installing/updating openclaw packages is blocked to prevent self-update loops');
      }
    }

    if (this.policy.blockUninstall) {
      const match = this.matchCategory('package-uninstall', normalizedCommand);
      if (match) {
        return this.buildResult('package-uninstall', match,
          'Removing openclaw installation is blocked to prevent self-destruction');
      }
    }

    if (this.policy.blockGatewayControl) {
      const match = this.matchCategory('gateway-control', normalizedCommand);
      if (match) {
        return this.buildResult('gateway-control', match,
          'Gateway restart/stop is blocked - agents should not control their own process');
      }
    }

    if (this.policy.blockConfigEdit) {
      const match = this.matchCategory('config-edit', normalizedCommand);
      if (match) {
        return this.buildResult('config-edit', match,
          'Direct config file edits are blocked - use config API instead');
      }
    }

    if (this.policy.blockProcessKill) {
      const match = this.matchCategory('process-kill', normalizedCommand);
      if (match) {
        return this.buildResult('process-kill', match,
          'Killing gateway/openclaw processes is blocked');
      }
    }

    // Check custom patterns
    for (const pattern of this.customPatterns) {
      if (pattern.test(normalizedCommand)) {
        return this.buildResult('custom', pattern.source,
          'Command matches custom blocked pattern');
      }
    }

    // Command is allowed
    return {
      blocked: false,
      requiresApproval: false,
      reason: 'Command does not match any self-modification patterns',
      category: 'allowed',
    };
  }

  /**
   * Check multiple commands (e.g., from a script)
   */
  checkScript(commands: string[]): SelfModificationCheckResult[] {
    return commands.map(cmd => this.check(cmd));
  }

  /**
   * Check if any command in a script would be blocked
   */
  scriptHasBlockedCommands(commands: string[]): boolean {
    return commands.some(cmd => this.check(cmd).blocked);
  }

  /**
   * Update policy
   */
  updatePolicy(policy: Partial<SelfModificationPolicy>): void {
    this.policy = { ...this.policy, ...policy };
    
    if (policy.customPatterns) {
      this.customPatterns = policy.customPatterns.map(p => {
        const regexStr = p.replace(/\*/g, '.*').replace(/\?/g, '.');
        return new RegExp(regexStr, 'i');
      });
    }
  }

  /**
   * Get current policy
   */
  getPolicy(): SelfModificationPolicy {
    return { ...this.policy };
  }

  // ============ Private Methods ============

  private matchCategory(
    category: Exclude<SelfModificationCategory, 'allowed' | 'custom'>,
    command: string
  ): string | null {
    const patterns = PATTERNS[category];
    for (const pattern of patterns) {
      if (pattern.test(command)) {
        return pattern.source;
      }
    }
    return null;
  }

  private buildResult(
    category: SelfModificationCategory,
    matchedPattern: string,
    reason: string
  ): SelfModificationCheckResult {
    return {
      blocked: !this.policy.requireApproval,
      requiresApproval: this.policy.requireApproval,
      reason,
      category,
      matchedPattern,
    };
  }
}
