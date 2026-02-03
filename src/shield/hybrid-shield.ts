/**
 * Hybrid Injection Shield
 * 
 * Combines fast pattern matching with ML-based detection for comprehensive
 * protection against prompt injection attacks.
 * 
 * Detection flow:
 * 1. Fast pattern matching (existing regex patterns)
 * 2. For uncertain cases (no match or low confidence), run ML detector
 * 3. Combine results with configurable thresholds
 */

import { 
  ScanResult, 
  Threat, 
  ThreatLevel, 
  ShieldPolicy,
  PolicyAction 
} from '../types';
import { InjectionShield, ShieldOptions, ScanContext } from './injection-shield';
import { MLDetector, MLDetectorConfig, MLScanResult } from './ml-detector';

export interface HybridShieldConfig {
  /** Configuration for pattern-based detection */
  shield?: ShieldOptions;
  
  /** Configuration for ML-based detection */
  ml?: MLDetectorConfig;
  
  /** When to use ML detection */
  mlStrategy?: MLStrategy;
  
  /** Confidence threshold below which ML is triggered for uncertain patterns */
  uncertaintyThreshold?: number;
  
  /** Weight for pattern-based score (0-1), ML weight = 1 - patternWeight */
  patternWeight?: number;
  
  /** Enable/disable ML detection */
  enableML?: boolean;
  
  /** Log detailed detection info */
  verbose?: boolean;
}

export type MLStrategy = 
  | 'always'           // Always run ML after patterns
  | 'on_uncertain'     // Run ML when pattern confidence is low
  | 'on_miss'          // Run ML only when patterns don't match
  | 'fallback';        // Run ML only as fallback (patterns disabled)

export interface HybridScanResult extends ScanResult {
  /** Results from pattern-based detection */
  patternResult?: ScanResult;
  
  /** Results from ML detection */
  mlResult?: MLScanResult;
  
  /** Which detectors contributed to the result */
  detectors: ('pattern' | 'ml')[];
  
  /** Combined processing time */
  totalProcessingTimeMs: number;
}

/**
 * Hybrid Shield combining pattern matching and ML detection
 */
export class HybridShield {
  private patternShield: InjectionShield;
  private mlDetector: MLDetector;
  private config: Required<HybridShieldConfig>;
  private initialized: boolean = false;

  constructor(config: HybridShieldConfig = {}) {
    this.config = {
      shield: config.shield ?? {},
      ml: config.ml ?? {},
      mlStrategy: config.mlStrategy ?? 'on_uncertain',
      uncertaintyThreshold: config.uncertaintyThreshold ?? 0.7,
      patternWeight: config.patternWeight ?? 0.6,
      enableML: config.enableML ?? true,
      verbose: config.verbose ?? false
    };

    this.patternShield = new InjectionShield(this.config.shield);
    this.mlDetector = new MLDetector(this.config.ml);
  }

  /**
   * Initialize the hybrid shield (loads ML models if needed)
   */
  async initialize(): Promise<void> {
    if (this.initialized) return;

    if (this.config.enableML) {
      await this.mlDetector.initialize();
    }

    this.initialized = true;
  }

  /**
   * Scan content for injection attempts using hybrid detection
   */
  async scan(content: string, context?: ScanContext): Promise<HybridScanResult> {
    const startTime = Date.now();

    // Ensure initialized
    if (!this.initialized) {
      await this.initialize();
    }

    // Strategy: fallback - only use ML
    if (this.config.mlStrategy === 'fallback') {
      return this.mlOnlyMode(content, startTime);
    }

    // Run pattern matching first (fast)
    const patternResult = this.patternShield.scan(content, context);
    
    // Determine if ML should run
    const shouldRunML = this.shouldRunML(patternResult);

    if (!shouldRunML) {
      return this.patternOnlyResult(patternResult, startTime);
    }

    // Run ML detection
    const mlResult = await this.mlDetector.scan(content);
    
    // Combine results
    return this.combineResults(content, patternResult, mlResult, startTime);
  }

  /**
   * Quick check - returns true if content appears safe
   */
  async isSafe(content: string): Promise<boolean> {
    const result = await this.scan(content);
    return result.safe;
  }

  /**
   * Synchronous pattern-only scan (for quick checks)
   */
  scanPatternOnly(content: string, context?: ScanContext): ScanResult {
    return this.patternShield.scan(content, context);
  }

  /**
   * Determine if ML detection should run based on strategy
   */
  private shouldRunML(patternResult: ScanResult): boolean {
    if (!this.config.enableML || !this.mlDetector.isAvailable()) {
      return false;
    }

    switch (this.config.mlStrategy) {
      case 'always':
        return true;

      case 'on_miss':
        return patternResult.safe && patternResult.threats.length === 0;

      case 'on_uncertain':
        // Run ML if no threats or low confidence threats
        if (patternResult.threats.length === 0) return true;
        const maxConfidence = Math.max(...patternResult.threats.map(t => t.confidence));
        return maxConfidence < this.config.uncertaintyThreshold;

      case 'fallback':
        return true;

      default:
        return false;
    }
  }

  /**
   * ML-only mode result
   */
  private async mlOnlyMode(content: string, startTime: number): Promise<HybridScanResult> {
    const mlResult = await this.mlDetector.scan(content);
    const threat = this.mlDetector.toThreat(mlResult, content);
    const threats = threat ? [threat] : [];

    return {
      safe: !mlResult.isInjection,
      threatLevel: threat?.severity ?? ThreatLevel.NONE,
      threats,
      metadata: {
        scanTimestamp: new Date().toISOString(),
        method: 'ml_only',
        mlMethod: mlResult.method
      },
      mlResult,
      detectors: ['ml'],
      totalProcessingTimeMs: Date.now() - startTime
    };
  }

  /**
   * Pattern-only result (ML not triggered)
   */
  private patternOnlyResult(patternResult: ScanResult, startTime: number): HybridScanResult {
    return {
      ...patternResult,
      patternResult,
      detectors: ['pattern'],
      totalProcessingTimeMs: Date.now() - startTime,
      metadata: {
        ...patternResult.metadata,
        method: 'pattern_only'
      }
    };
  }

  /**
   * Combine pattern and ML results
   */
  private combineResults(
    content: string,
    patternResult: ScanResult,
    mlResult: MLScanResult,
    startTime: number
  ): HybridScanResult {
    const threats: Threat[] = [...patternResult.threats];
    
    // Add ML threat if detected
    const mlThreat = this.mlDetector.toThreat(mlResult, content);
    if (mlThreat) {
      // Check if this is a new detection (not already caught by patterns)
      const isDuplicate = this.isDuplicateThreat(mlThreat, patternResult.threats);
      if (!isDuplicate) {
        threats.push(mlThreat);
      }
    }

    // Calculate combined threat level
    const threatLevel = this.calculateCombinedThreatLevel(patternResult, mlResult, threats);

    // Determine if safe
    const patternSafe = patternResult.safe;
    const mlSafe = !mlResult.isInjection;
    
    // Content is safe only if both agree it's safe
    // With weighted consideration
    const safe = this.calculateSafeStatus(patternSafe, mlSafe, patternResult, mlResult);

    if (this.config.verbose) {
      console.log('[HybridShield] Detection results:', {
        patternSafe,
        mlSafe,
        patternThreats: patternResult.threats.length,
        mlConfidence: mlResult.confidence,
        combinedSafe: safe,
        threatLevel
      });
    }

    return {
      safe,
      threatLevel,
      threats,
      metadata: {
        scanTimestamp: new Date().toISOString(),
        method: 'hybrid',
        patternMatches: patternResult.threats.length,
        mlConfidence: mlResult.confidence,
        mlMethod: mlResult.method
      },
      patternResult,
      mlResult,
      detectors: ['pattern', 'ml'],
      totalProcessingTimeMs: Date.now() - startTime
    };
  }

  /**
   * Check if ML threat duplicates a pattern threat
   */
  private isDuplicateThreat(mlThreat: Threat, patternThreats: Threat[]): boolean {
    // Consider it a duplicate if same type and similar severity
    return patternThreats.some(pt => 
      pt.type === mlThreat.type && 
      Math.abs(pt.severity - mlThreat.severity) <= 1
    );
  }

  /**
   * Calculate combined threat level from both detectors
   */
  private calculateCombinedThreatLevel(
    patternResult: ScanResult,
    mlResult: MLScanResult,
    combinedThreats: Threat[]
  ): ThreatLevel {
    if (combinedThreats.length === 0) {
      return ThreatLevel.NONE;
    }

    const maxThreatLevel = Math.max(...combinedThreats.map(t => t.severity));

    // Boost severity if both detectors agree
    const patternDetected = patternResult.threats.length > 0;
    const mlDetected = mlResult.isInjection;

    if (patternDetected && mlDetected) {
      // Both agree - boost confidence, possibly increase severity
      if (maxThreatLevel < ThreatLevel.CRITICAL && mlResult.confidence >= 0.85) {
        return Math.min(ThreatLevel.CRITICAL, maxThreatLevel + 1) as ThreatLevel;
      }
    }

    return maxThreatLevel;
  }

  /**
   * Calculate safe status with weighted combination
   */
  private calculateSafeStatus(
    patternSafe: boolean,
    mlSafe: boolean,
    patternResult: ScanResult,
    mlResult: MLScanResult
  ): boolean {
    // If both agree, that's the answer
    if (patternSafe === mlSafe) {
      return patternSafe;
    }

    // They disagree - use weighted decision
    const patternWeight = this.config.patternWeight;
    const mlWeight = 1 - patternWeight;

    // Calculate scores
    const patternScore = patternSafe ? 0 : (patternResult.threatLevel / ThreatLevel.CRITICAL);
    const mlScore = mlSafe ? 0 : mlResult.confidence;

    const combinedScore = patternScore * patternWeight + mlScore * mlWeight;

    // Threshold at 0.4 - lower than 0.5 to be more cautious
    return combinedScore < 0.4;
  }

  /**
   * Get recommended action based on scan result
   */
  getAction(result: HybridScanResult): PolicyAction {
    return this.patternShield.getAction(result);
  }

  /**
   * Update shield policy
   */
  updatePolicy(policy: Partial<ShieldPolicy>): void {
    this.patternShield.updatePolicy(policy);
  }

  /**
   * Update ML configuration
   */
  updateMLConfig(config: Partial<MLDetectorConfig>): void {
    this.mlDetector.updateConfig(config);
    this.initialized = false; // Re-initialize on next scan
  }

  /**
   * Update hybrid configuration
   */
  updateConfig(config: Partial<HybridShieldConfig>): void {
    Object.assign(this.config, config);
    
    if (config.shield) {
      this.patternShield = new InjectionShield(config.shield);
    }
    if (config.ml) {
      this.mlDetector.updateConfig(config.ml);
      this.initialized = false;
    }
  }

  /**
   * Add to allowlist
   */
  addToAllowlist(sourceId: string): void {
    this.patternShield.addToAllowlist(sourceId);
  }

  /**
   * Remove from allowlist
   */
  removeFromAllowlist(sourceId: string): void {
    this.patternShield.removeFromAllowlist(sourceId);
  }

  /**
   * Get detection method status
   */
  getStatus(): {
    patternReady: boolean;
    mlReady: boolean;
    mlMethod: 'embedding' | 'tfidf' | 'none';
    strategy: MLStrategy;
  } {
    return {
      patternReady: true, // Pattern matching is always ready
      mlReady: this.mlDetector.isAvailable(),
      mlMethod: this.mlDetector.getMethod(),
      strategy: this.config.mlStrategy
    };
  }

  /**
   * Run benchmark comparing pattern vs ML detection
   */
  async benchmark(testCases: Array<{ text: string; expected: boolean }>): Promise<{
    patternAccuracy: number;
    mlAccuracy: number;
    hybridAccuracy: number;
    avgPatternTimeMs: number;
    avgMLTimeMs: number;
    avgHybridTimeMs: number;
    results: Array<{
      text: string;
      expected: boolean;
      patternResult: boolean;
      mlResult: boolean;
      hybridResult: boolean;
    }>;
  }> {
    await this.initialize();

    let patternCorrect = 0;
    let mlCorrect = 0;
    let hybridCorrect = 0;
    let totalPatternTime = 0;
    let totalMLTime = 0;
    let totalHybridTime = 0;

    const results: Array<{
      text: string;
      expected: boolean;
      patternResult: boolean;
      mlResult: boolean;
      hybridResult: boolean;
    }> = [];

    for (const testCase of testCases) {
      // Pattern only
      const patternStart = Date.now();
      const patternScan = this.patternShield.scan(testCase.text);
      totalPatternTime += Date.now() - patternStart;
      const patternDetected = !patternScan.safe;

      // ML only
      const mlStart = Date.now();
      const mlScan = await this.mlDetector.scan(testCase.text);
      totalMLTime += Date.now() - mlStart;
      const mlDetected = mlScan.isInjection;

      // Hybrid
      const hybridStart = Date.now();
      const hybridScan = await this.scan(testCase.text);
      totalHybridTime += Date.now() - hybridStart;
      const hybridDetected = !hybridScan.safe;

      // Check correctness
      if (patternDetected === testCase.expected) patternCorrect++;
      if (mlDetected === testCase.expected) mlCorrect++;
      if (hybridDetected === testCase.expected) hybridCorrect++;

      results.push({
        text: testCase.text.substring(0, 50) + (testCase.text.length > 50 ? '...' : ''),
        expected: testCase.expected,
        patternResult: patternDetected,
        mlResult: mlDetected,
        hybridResult: hybridDetected
      });
    }

    const n = testCases.length;
    return {
      patternAccuracy: n > 0 ? patternCorrect / n : 0,
      mlAccuracy: n > 0 ? mlCorrect / n : 0,
      hybridAccuracy: n > 0 ? hybridCorrect / n : 0,
      avgPatternTimeMs: n > 0 ? totalPatternTime / n : 0,
      avgMLTimeMs: n > 0 ? totalMLTime / n : 0,
      avgHybridTimeMs: n > 0 ? totalHybridTime / n : 0,
      results
    };
  }
}

/**
 * Factory function for quick setup
 */
export function createHybridShield(options?: {
  useEmbeddings?: boolean;
  apiKey?: string;
  strategy?: MLStrategy;
  sensitivity?: 'low' | 'medium' | 'high';
}): HybridShield {
  return new HybridShield({
    shield: {
      policy: options?.sensitivity ? { sensitivity: options.sensitivity } : undefined
    },
    ml: {
      useEmbeddings: options?.useEmbeddings ?? false,
      apiKey: options?.apiKey,
      enableLocalFallback: true
    },
    mlStrategy: options?.strategy ?? 'on_uncertain',
    enableML: true
  });
}
