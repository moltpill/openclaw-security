/**
 * Injection Shield
 * 
 * Scans content for prompt injection attempts and returns
 * a threat assessment with details about detected threats.
 */

import { 
  ScanResult, 
  Threat, 
  ThreatLevel, 
  ShieldPolicy,
  PolicyAction 
} from '../types';
import { 
  INJECTION_PATTERNS, 
  InjectionPattern,
  CONTEXT_MODIFIERS,
  getMaxSeverity 
} from './injection-patterns';

export interface ShieldOptions {
  policy?: Partial<ShieldPolicy>;
  customPatterns?: InjectionPattern[];
}

export class InjectionShield {
  private patterns: InjectionPattern[];
  private policy: ShieldPolicy;
  private allowlist: Set<string>;

  constructor(options: ShieldOptions = {}) {
    // Merge default patterns with custom ones
    this.patterns = [
      ...INJECTION_PATTERNS,
      ...(options.customPatterns || [])
    ];

    // Default policy
    this.policy = {
      enabled: true,
      sensitivity: 'medium',
      customPatterns: [],
      allowlist: [],
      actions: {
        onLow: 'allow',
        onMedium: 'warn',
        onHigh: 'block',
        onCritical: 'block'
      },
      ...options.policy
    };

    this.allowlist = new Set(this.policy.allowlist || []);
  }

  /**
   * Scan content for prompt injection attempts
   */
  scan(content: string, context?: ScanContext): ScanResult {
    if (!this.policy.enabled) {
      return this.safeScanResult();
    }

    // Check allowlist
    if (context?.sourceId && this.allowlist.has(context.sourceId)) {
      return this.safeScanResult({ allowlisted: true });
    }

    const threats: Threat[] = [];
    const normalizedContent = this.normalizeContent(content);

    // Run all pattern checks
    for (const pattern of this.patterns) {
      const matches = this.findMatches(normalizedContent, pattern, content);
      threats.push(...matches);
    }

    // Apply context modifiers
    if (context) {
      this.applyContextModifiers(threats, context);
    }

    // Apply sensitivity threshold
    const filteredThreats = this.filterBySensitivity(threats);

    // Calculate overall threat level
    const threatLevel = this.calculateThreatLevel(filteredThreats);

    return {
      safe: threatLevel <= ThreatLevel.LOW,
      threatLevel,
      threats: filteredThreats,
      metadata: {
        totalPatternMatches: threats.length,
        filteredMatches: filteredThreats.length,
        sensitivity: this.policy.sensitivity,
        scanTimestamp: new Date().toISOString()
      }
    };
  }

  /**
   * Quick check - returns true if content appears safe
   */
  isSafe(content: string): boolean {
    const result = this.scan(content);
    return result.safe;
  }

  /**
   * Get recommended action based on scan result
   */
  getAction(result: ScanResult): PolicyAction {
    switch (result.threatLevel) {
      case ThreatLevel.NONE:
      case ThreatLevel.LOW:
        return this.policy.actions.onLow;
      case ThreatLevel.MEDIUM:
        return this.policy.actions.onMedium;
      case ThreatLevel.HIGH:
        return this.policy.actions.onHigh;
      case ThreatLevel.CRITICAL:
        return this.policy.actions.onCritical;
      default:
        return 'block';
    }
  }

  /**
   * Normalize content for pattern matching
   */
  private normalizeContent(content: string): string {
    return content
      .toLowerCase()
      // Normalize whitespace
      .replace(/\s+/g, ' ')
      // Remove markdown formatting
      .replace(/[*_~`]/g, '')
      // Normalize quotes
      .replace(/[""]/g, '"')
      .replace(/['']/g, "'");
  }

  /**
   * Find all matches for a pattern in content
   */
  private findMatches(
    normalizedContent: string, 
    pattern: InjectionPattern,
    originalContent: string
  ): Threat[] {
    const threats: Threat[] = [];
    
    // Reset regex state
    pattern.pattern.lastIndex = 0;
    
    let match;
    while ((match = pattern.pattern.exec(normalizedContent)) !== null) {
      // Find location in original content
      const location = this.findOriginalLocation(originalContent, match.index, match[0].length);
      
      threats.push({
        type: pattern.type,
        severity: pattern.severity,
        description: pattern.description,
        location,
        pattern: pattern.name,
        confidence: pattern.confidence
      });

      // Prevent infinite loop for zero-length matches
      if (match.index === pattern.pattern.lastIndex) {
        pattern.pattern.lastIndex++;
      }
    }

    // Reset for next use
    pattern.pattern.lastIndex = 0;

    return threats;
  }

  /**
   * Find the location in original content
   */
  private findOriginalLocation(
    originalContent: string, 
    normalizedIndex: number, 
    length: number
  ): Threat['location'] {
    // Approximate - normalized content may have different positions
    const start = Math.min(normalizedIndex, originalContent.length - 1);
    const end = Math.min(start + length, originalContent.length);
    
    // Find line number
    const beforeMatch = originalContent.substring(0, start);
    const line = (beforeMatch.match(/\n/g) || []).length + 1;

    return { start, end, line };
  }

  /**
   * Apply context-based modifiers to threat confidence
   */
  private applyContextModifiers(threats: Threat[], context: ScanContext): void {
    for (const threat of threats) {
      let modifier = 1.0;

      // Adjust for external content
      if (context.isExternalContent) {
        modifier *= CONTEXT_MODIFIERS.externalContent;
      }

      // Adjust for trusted source
      if (context.isTrustedSource) {
        modifier *= CONTEXT_MODIFIERS.trustedSource;
      }

      // Adjust for multiple matches
      if (threats.length > 2) {
        modifier *= CONTEXT_MODIFIERS.multipleMatches;
      }

      // Apply modifier to confidence
      threat.confidence = Math.min(1, threat.confidence * modifier);
    }
  }

  /**
   * Filter threats based on sensitivity setting
   */
  private filterBySensitivity(threats: Threat[]): Threat[] {
    const minSeverity = this.getMinSeverityForSensitivity();
    return threats.filter(t => t.severity >= minSeverity);
  }

  /**
   * Get minimum severity to report based on sensitivity
   */
  private getMinSeverityForSensitivity(): ThreatLevel {
    switch (this.policy.sensitivity) {
      case 'low':
        return ThreatLevel.HIGH;
      case 'medium':
        return ThreatLevel.MEDIUM;
      case 'high':
        return ThreatLevel.LOW;
      default:
        return ThreatLevel.MEDIUM;
    }
  }

  /**
   * Calculate overall threat level from threats
   */
  private calculateThreatLevel(threats: Threat[]): ThreatLevel {
    if (threats.length === 0) return ThreatLevel.NONE;

    // Get max severity
    const maxSeverity = Math.max(...threats.map(t => t.severity));

    // Boost if multiple high-confidence threats
    const highConfidenceCount = threats.filter(t => t.confidence >= 0.8).length;
    if (highConfidenceCount >= 3 && maxSeverity < ThreatLevel.CRITICAL) {
      return Math.min(ThreatLevel.CRITICAL, maxSeverity + 1);
    }

    return maxSeverity;
  }

  /**
   * Return a safe scan result
   */
  private safeScanResult(metadata: Record<string, unknown> = {}): ScanResult {
    return {
      safe: true,
      threatLevel: ThreatLevel.NONE,
      threats: [],
      metadata: {
        scanTimestamp: new Date().toISOString(),
        ...metadata
      }
    };
  }

  /**
   * Add pattern to allowlist
   */
  addToAllowlist(sourceId: string): void {
    this.allowlist.add(sourceId);
  }

  /**
   * Remove pattern from allowlist
   */
  removeFromAllowlist(sourceId: string): void {
    this.allowlist.delete(sourceId);
  }

  /**
   * Update policy
   */
  updatePolicy(policy: Partial<ShieldPolicy>): void {
    this.policy = { ...this.policy, ...policy };
    if (policy.allowlist) {
      this.allowlist = new Set(policy.allowlist);
    }
  }
}

/**
 * Context for scanning - provides additional info for severity calculation
 */
export interface ScanContext {
  sourceId?: string;
  isExternalContent?: boolean;
  isTrustedSource?: boolean;
  channel?: string;
  messagePosition?: 'start' | 'middle' | 'end';
}
