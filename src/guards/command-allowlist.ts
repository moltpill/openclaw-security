/**
 * CommandAllowlist - Pre-approved command patterns
 *
 * Commands matching the allowlist bypass the self-modification guard
 * and can optionally auto-elevate (inject `elevated: true` into exec params).
 *
 * Pattern syntax:
 *   - Exact: "tailscale status"
 *   - Glob:  "tailscale *" (matches "tailscale status", "tailscale ip -4", etc.)
 *   - Glob:  "sudo systemctl restart openclaw-*"
 *
 * Matching is case-insensitive and trimmed.
 */

export interface AllowlistConfig {
  enabled: boolean;
  /** Commands that bypass the self-modification guard */
  commands: string[];
  /** Commands that auto-inject elevated: true (typically sudo commands) */
  elevate: string[];
}

export interface AllowlistCheckResult {
  /** Command matched an allowlist pattern */
  allowed: boolean;
  /** Command should be auto-elevated (matched an elevate pattern) */
  autoElevate: boolean;
  /** The pattern that matched (for audit logging) */
  matchedPattern?: string;
}

/**
 * Convert a glob-like pattern to a regex.
 * `*` → match anything (including spaces), `?` → match one char.
 */
function globToRegex(pattern: string): RegExp {
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')  // escape regex specials (except * and ?)
    .replace(/\*/g, '.*')                    // * → .*
    .replace(/\?/g, '.');                    // ? → .
  return new RegExp(`^${escaped}$`, 'i');
}

export class CommandAllowlist {
  private commandPatterns: { regex: RegExp; source: string }[] = [];
  private elevatePatterns: { regex: RegExp; source: string }[] = [];
  private enabled: boolean;

  constructor(config: AllowlistConfig) {
    this.enabled = config.enabled;
    this.commandPatterns = config.commands.map((p) => ({
      regex: globToRegex(p),
      source: p,
    }));
    this.elevatePatterns = config.elevate.map((p) => ({
      regex: globToRegex(p),
      source: p,
    }));
  }

  /**
   * Check a command against the allowlist.
   */
  check(command: string): AllowlistCheckResult {
    if (!this.enabled) {
      return { allowed: false, autoElevate: false };
    }

    const normalized = command.trim();

    // Check elevate patterns first (elevate implies allowed)
    for (const pattern of this.elevatePatterns) {
      if (pattern.regex.test(normalized)) {
        return {
          allowed: true,
          autoElevate: true,
          matchedPattern: pattern.source,
        };
      }
    }

    // Check command allowlist patterns
    for (const pattern of this.commandPatterns) {
      if (pattern.regex.test(normalized)) {
        return {
          allowed: true,
          autoElevate: false,
          matchedPattern: pattern.source,
        };
      }
    }

    return { allowed: false, autoElevate: false };
  }

  /**
   * Update the allowlist config at runtime.
   */
  update(config: Partial<AllowlistConfig>): void {
    if (config.enabled !== undefined) this.enabled = config.enabled;
    if (config.commands) {
      this.commandPatterns = config.commands.map((p) => ({
        regex: globToRegex(p),
        source: p,
      }));
    }
    if (config.elevate) {
      this.elevatePatterns = config.elevate.map((p) => ({
        regex: globToRegex(p),
        source: p,
      }));
    }
  }
}
