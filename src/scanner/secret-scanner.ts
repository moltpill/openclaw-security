/**
 * Secret Scanner
 * 
 * Scans files and content for API keys, tokens, passwords,
 * and other sensitive data.
 */

import * as fs from 'fs';
import * as path from 'path';
import { 
  ScanResult, 
  Threat, 
  ThreatLevel, 
  ThreatType,
  ScannerPolicy 
} from '../types';
import { 
  SECRET_PATTERNS, 
  SecretPattern,
  SENSITIVE_EXTENSIONS,
  SENSITIVE_PATHS 
} from './secret-patterns';

export interface SecretScannerOptions {
  policy?: Partial<ScannerPolicy>;
  customPatterns?: SecretPattern[];
}

export interface FileScanResult extends ScanResult {
  filePath: string;
  fileSize: number;
}

export class SecretScanner {
  private patterns: SecretPattern[];
  private policy: ScannerPolicy;

  constructor(options: SecretScannerOptions = {}) {
    this.patterns = [
      ...SECRET_PATTERNS,
      ...(options.customPatterns || [])
    ];

    this.policy = {
      enabled: true,
      scanOnStartup: true,
      extensions: ['.md', '.yaml', '.yml', '.json', '.env', '.txt', '.js', '.ts', '.py'],
      excludePaths: ['node_modules/', '.git/', 'dist/', 'build/'],
      customPatterns: [],
      actions: {
        onRead: 'warn',
        onWrite: 'block',
        onExisting: 'report'
      },
      ...options.policy
    };
  }

  /**
   * Scan content string for secrets
   */
  scan(content: string, sourcePath?: string): ScanResult {
    if (!this.policy.enabled) {
      return this.safeScanResult();
    }

    const threats: Threat[] = [];

    for (const pattern of this.patterns) {
      const matches = this.findMatches(content, pattern);
      threats.push(...matches);
    }

    // Calculate overall threat level
    const threatLevel = this.calculateThreatLevel(threats);

    return {
      safe: threats.length === 0,
      threatLevel,
      threats,
      metadata: {
        totalPatternMatches: threats.length,
        scanTimestamp: new Date().toISOString(),
        sourcePath
      }
    };
  }

  /**
   * Scan a file for secrets
   */
  async scanFile(filePath: string): Promise<FileScanResult> {
    if (!this.policy.enabled) {
      return {
        ...this.safeScanResult(),
        filePath,
        fileSize: 0
      };
    }

    // Check if file should be excluded
    if (this.shouldExclude(filePath)) {
      return {
        ...this.safeScanResult(),
        filePath,
        fileSize: 0,
        metadata: { excluded: true }
      };
    }

    try {
      const stats = await fs.promises.stat(filePath);
      const content = await fs.promises.readFile(filePath, 'utf-8');
      const result = this.scan(content, filePath);

      // Check if it's a sensitive file type
      const isSensitiveFile = this.isSensitiveFile(filePath);
      if (isSensitiveFile && result.threats.length === 0) {
        result.threats.push({
          type: ThreatType.SUSPICIOUS_PATTERN,
          severity: ThreatLevel.MEDIUM,
          description: 'File in sensitive location or with sensitive extension',
          confidence: 0.6
        });
        result.threatLevel = Math.max(result.threatLevel, ThreatLevel.MEDIUM);
        result.safe = false;
      }

      return {
        ...result,
        filePath,
        fileSize: stats.size
      };
    } catch (error) {
      return {
        safe: true,
        threatLevel: ThreatLevel.NONE,
        threats: [],
        metadata: {
          error: error instanceof Error ? error.message : 'Unknown error',
          scanTimestamp: new Date().toISOString()
        },
        filePath,
        fileSize: 0
      };
    }
  }

  /**
   * Scan a directory recursively
   */
  async scanDirectory(dirPath: string): Promise<FileScanResult[]> {
    const results: FileScanResult[] = [];

    try {
      const entries = await fs.promises.readdir(dirPath, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = path.join(dirPath, entry.name);

        if (this.shouldExclude(fullPath)) {
          continue;
        }

        if (entry.isDirectory()) {
          const subResults = await this.scanDirectory(fullPath);
          results.push(...subResults);
        } else if (entry.isFile()) {
          // Check extension
          const ext = path.extname(entry.name).toLowerCase();
          const basename = path.basename(entry.name).toLowerCase();
          
          if (this.policy.extensions.includes(ext) || 
              this.policy.extensions.some(e => basename.endsWith(e))) {
            const result = await this.scanFile(fullPath);
            if (!result.safe) {
              results.push(result);
            }
          }
        }
      }
    } catch (error) {
      // Directory access error - continue
    }

    return results;
  }

  /**
   * Scan content and redact secrets
   */
  redact(content: string): { redacted: string; secretsFound: number } {
    let redacted = content;
    let secretsFound = 0;

    for (const pattern of this.patterns) {
      // Reset regex state
      pattern.pattern.lastIndex = 0;
      
      const matches = content.match(pattern.pattern);
      if (matches) {
        secretsFound += matches.length;
        
        for (const match of matches) {
          // Keep first and last 4 chars, redact middle
          const redactedMatch = this.redactSecret(match, pattern.name);
          redacted = redacted.replace(match, redactedMatch);
        }
      }
      
      pattern.pattern.lastIndex = 0;
    }

    return { redacted, secretsFound };
  }

  /**
   * Redact a single secret value
   */
  private redactSecret(value: string, patternName: string): string {
    if (value.length <= 8) {
      return `[REDACTED:${patternName}]`;
    }
    
    const prefix = value.substring(0, 4);
    const suffix = value.substring(value.length - 4);
    const redactedLength = value.length - 8;
    
    return `${prefix}${'*'.repeat(Math.min(redactedLength, 20))}${suffix}`;
  }

  /**
   * Find all matches for a pattern
   */
  private findMatches(content: string, pattern: SecretPattern): Threat[] {
    const threats: Threat[] = [];
    
    // Reset regex state
    pattern.pattern.lastIndex = 0;
    
    let match;
    while ((match = pattern.pattern.exec(content)) !== null) {
      // Find line number
      const beforeMatch = content.substring(0, match.index);
      const line = (beforeMatch.match(/\n/g) || []).length + 1;

      threats.push({
        type: pattern.type,
        severity: pattern.severity,
        description: pattern.description,
        location: {
          start: match.index,
          end: match.index + match[0].length,
          line
        },
        pattern: pattern.name,
        confidence: pattern.requiresValidation ? 0.7 : 0.95
      });

      // Prevent infinite loop
      if (match.index === pattern.pattern.lastIndex) {
        pattern.pattern.lastIndex++;
      }
    }

    // Reset for next use
    pattern.pattern.lastIndex = 0;

    return threats;
  }

  /**
   * Check if a path should be excluded
   */
  private shouldExclude(filePath: string): boolean {
    const normalizedPath = filePath.replace(/\\/g, '/');
    return this.policy.excludePaths.some(exclude => 
      normalizedPath.includes(exclude)
    );
  }

  /**
   * Check if a file is in a sensitive location or has sensitive extension
   */
  private isSensitiveFile(filePath: string): boolean {
    const normalizedPath = filePath.replace(/\\/g, '/').toLowerCase();
    const ext = path.extname(filePath).toLowerCase();
    const basename = path.basename(filePath).toLowerCase();

    // Check sensitive extensions
    if (SENSITIVE_EXTENSIONS.some(e => basename.endsWith(e) || ext === e)) {
      return true;
    }

    // Check sensitive paths
    if (SENSITIVE_PATHS.some(p => normalizedPath.includes(p.toLowerCase()))) {
      return true;
    }

    return false;
  }

  /**
   * Calculate overall threat level
   */
  private calculateThreatLevel(threats: Threat[]): ThreatLevel {
    if (threats.length === 0) return ThreatLevel.NONE;
    return Math.max(...threats.map(t => t.severity));
  }

  /**
   * Return a safe scan result
   */
  private safeScanResult(): ScanResult {
    return {
      safe: true,
      threatLevel: ThreatLevel.NONE,
      threats: [],
      metadata: {
        scanTimestamp: new Date().toISOString()
      }
    };
  }

  /**
   * Get action based on operation type
   */
  getAction(operation: 'read' | 'write' | 'existing'): string {
    switch (operation) {
      case 'read':
        return this.policy.actions.onRead;
      case 'write':
        return this.policy.actions.onWrite;
      case 'existing':
        return this.policy.actions.onExisting;
      default:
        return 'warn';
    }
  }

  /**
   * Update policy
   */
  updatePolicy(policy: Partial<ScannerPolicy>): void {
    this.policy = { ...this.policy, ...policy };
  }

  /**
   * Add custom pattern
   */
  addPattern(pattern: SecretPattern): void {
    this.patterns.push(pattern);
  }
}
