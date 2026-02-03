/**
 * ML-based Injection Detector
 * 
 * Uses embedding similarity and/or a trained classifier to detect
 * prompt injection attacks that bypass pattern matching.
 * 
 * Two modes:
 * 1. Embedding mode (requires API key): Uses OpenAI/local embeddings for semantic similarity
 * 2. Local mode (no API): Uses TF-IDF with cosine similarity
 */

import { ThreatLevel, ThreatType, Threat } from '../types';
import { 
  INJECTION_EXAMPLES, 
  BENIGN_EXAMPLES, 
  TrainingExample,
  getInjectionTexts 
} from './training-data';

export interface MLDetectorConfig {
  /** Use OpenAI embeddings (requires OPENAI_API_KEY env var) */
  useEmbeddings?: boolean;
  
  /** OpenAI API key (falls back to OPENAI_API_KEY env) */
  apiKey?: string;
  
  /** Embedding model to use */
  embeddingModel?: string;
  
  /** Similarity threshold for injection detection (0-1) */
  similarityThreshold?: number;
  
  /** Confidence threshold for returning results (0-1) */
  confidenceThreshold?: number;
  
  /** Cache embeddings to disk */
  cacheEmbeddings?: boolean;
  
  /** Path for embedding cache */
  cachePath?: string;

  /** Enable local TF-IDF fallback when embeddings unavailable */
  enableLocalFallback?: boolean;
}

export interface MLScanResult {
  isInjection: boolean;
  confidence: number;
  method: 'embedding' | 'tfidf' | 'hybrid';
  similarExamples?: Array<{
    text: string;
    similarity: number;
    category?: ThreatType;
  }>;
  processingTimeMs: number;
}

interface EmbeddingCache {
  model: string;
  examples: Map<string, number[]>;
  timestamp: number;
}

/**
 * TF-IDF based similarity calculator (no external deps)
 */
class TFIDFCalculator {
  private vocabulary: Map<string, number> = new Map();
  private idf: Map<string, number> = new Map();
  private documentVectors: Map<string, number[]> = new Map();
  private documents: string[] = [];

  constructor(documents: string[]) {
    this.documents = documents;
    this.buildVocabulary();
    this.calculateIDF();
    this.buildDocumentVectors();
  }

  private tokenize(text: string): string[] {
    return text
      .toLowerCase()
      .replace(/[^\w\s]/g, ' ')
      .split(/\s+/)
      .filter(t => t.length > 1);
  }

  private buildVocabulary(): void {
    const allTokens = new Set<string>();
    for (const doc of this.documents) {
      for (const token of this.tokenize(doc)) {
        allTokens.add(token);
      }
    }
    let idx = 0;
    for (const token of allTokens) {
      this.vocabulary.set(token, idx++);
    }
  }

  private calculateIDF(): void {
    const docCount = this.documents.length;
    const tokenDocCounts = new Map<string, number>();

    for (const doc of this.documents) {
      const uniqueTokens = new Set(this.tokenize(doc));
      for (const token of uniqueTokens) {
        tokenDocCounts.set(token, (tokenDocCounts.get(token) || 0) + 1);
      }
    }

    for (const [token, count] of tokenDocCounts) {
      // IDF with smoothing
      this.idf.set(token, Math.log((docCount + 1) / (count + 1)) + 1);
    }
  }

  private buildDocumentVectors(): void {
    for (const doc of this.documents) {
      this.documentVectors.set(doc, this.getVector(doc));
    }
  }

  private getVector(text: string): number[] {
    const tokens = this.tokenize(text);
    const tf = new Map<string, number>();
    
    // Calculate term frequency
    for (const token of tokens) {
      tf.set(token, (tf.get(token) || 0) + 1);
    }

    // Build TF-IDF vector
    const vector = new Array(this.vocabulary.size).fill(0);
    for (const [token, freq] of tf) {
      const idx = this.vocabulary.get(token);
      if (idx !== undefined) {
        const idfValue = this.idf.get(token) || 1;
        vector[idx] = (freq / tokens.length) * idfValue;
      }
    }

    return vector;
  }

  private cosineSimilarity(a: number[], b: number[]): number {
    let dotProduct = 0;
    let normA = 0;
    let normB = 0;

    for (let i = 0; i < a.length; i++) {
      dotProduct += a[i] * b[i];
      normA += a[i] * a[i];
      normB += b[i] * b[i];
    }

    if (normA === 0 || normB === 0) return 0;
    return dotProduct / (Math.sqrt(normA) * Math.sqrt(normB));
  }

  /**
   * Find most similar documents to the query
   */
  findSimilar(query: string, topK: number = 5): Array<{ text: string; similarity: number }> {
    const queryVector = this.getVector(query);
    const similarities: Array<{ text: string; similarity: number }> = [];

    for (const [doc, docVector] of this.documentVectors) {
      const similarity = this.cosineSimilarity(queryVector, docVector);
      similarities.push({ text: doc, similarity });
    }

    return similarities
      .sort((a, b) => b.similarity - a.similarity)
      .slice(0, topK);
  }

  /**
   * Get maximum similarity to any document
   */
  getMaxSimilarity(query: string): number {
    const similar = this.findSimilar(query, 1);
    return similar.length > 0 ? similar[0].similarity : 0;
  }
}

/**
 * ML-based Injection Detector
 */
export class MLDetector {
  private config: Required<MLDetectorConfig>;
  private tfidfCalculator: TFIDFCalculator | null = null;
  private embeddingCache: EmbeddingCache | null = null;
  private injectionExamples: TrainingExample[];
  private benignExamples: TrainingExample[];
  private initialized: boolean = false;

  constructor(config: MLDetectorConfig = {}) {
    this.config = {
      useEmbeddings: config.useEmbeddings ?? false,
      apiKey: config.apiKey ?? process.env.OPENAI_API_KEY ?? '',
      embeddingModel: config.embeddingModel ?? 'text-embedding-3-small',
      similarityThreshold: config.similarityThreshold ?? 0.75,
      confidenceThreshold: config.confidenceThreshold ?? 0.5,
      cacheEmbeddings: config.cacheEmbeddings ?? true,
      cachePath: config.cachePath ?? '.clawguard-embeddings.json',
      enableLocalFallback: config.enableLocalFallback ?? true
    };

    this.injectionExamples = INJECTION_EXAMPLES;
    this.benignExamples = BENIGN_EXAMPLES;
  }

  /**
   * Initialize the detector (load embeddings or build TF-IDF)
   */
  async initialize(): Promise<void> {
    if (this.initialized) return;

    if (this.config.useEmbeddings && this.config.apiKey) {
      try {
        await this.initializeEmbeddings();
        this.initialized = true;
        return;
      } catch (error) {
        console.warn('Failed to initialize embeddings, falling back to TF-IDF:', error);
      }
    }

    if (this.config.enableLocalFallback) {
      this.initializeTFIDF();
    }

    this.initialized = true;
  }

  /**
   * Initialize TF-IDF based detection
   */
  private initializeTFIDF(): void {
    const injectionTexts = this.injectionExamples.map(e => e.text);
    this.tfidfCalculator = new TFIDFCalculator(injectionTexts);
  }

  /**
   * Initialize embedding-based detection
   */
  private async initializeEmbeddings(): Promise<void> {
    // Try to load cached embeddings
    if (this.config.cacheEmbeddings) {
      const cached = await this.loadEmbeddingCache();
      if (cached && cached.model === this.config.embeddingModel) {
        this.embeddingCache = cached;
        return;
      }
    }

    // Generate embeddings for all examples
    const injectionTexts = this.injectionExamples.map(e => e.text);
    const embeddings = await this.generateEmbeddings(injectionTexts);

    this.embeddingCache = {
      model: this.config.embeddingModel,
      examples: new Map(injectionTexts.map((t, i) => [t, embeddings[i]])),
      timestamp: Date.now()
    };

    // Cache to disk
    if (this.config.cacheEmbeddings) {
      await this.saveEmbeddingCache();
    }
  }

  /**
   * Generate embeddings using OpenAI API
   */
  private async generateEmbeddings(texts: string[]): Promise<number[][]> {
    const batchSize = 100;
    const allEmbeddings: number[][] = [];

    for (let i = 0; i < texts.length; i += batchSize) {
      const batch = texts.slice(i, i + batchSize);
      const response = await fetch('https://api.openai.com/v1/embeddings', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.config.apiKey}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          model: this.config.embeddingModel,
          input: batch
        })
      });

      if (!response.ok) {
        throw new Error(`OpenAI API error: ${response.status}`);
      }

      const data = await response.json() as { data: Array<{ embedding: number[] }> };
      const embeddings = data.data.map((d) => d.embedding);
      allEmbeddings.push(...embeddings);
    }

    return allEmbeddings;
  }

  /**
   * Generate single embedding
   */
  private async generateEmbedding(text: string): Promise<number[]> {
    const [embedding] = await this.generateEmbeddings([text]);
    return embedding;
  }

  /**
   * Load embedding cache from disk
   */
  private async loadEmbeddingCache(): Promise<EmbeddingCache | null> {
    try {
      const fs = await import('fs').then(m => m.promises);
      const data = await fs.readFile(this.config.cachePath, 'utf-8');
      const parsed = JSON.parse(data);
      return {
        model: parsed.model,
        examples: new Map(Object.entries(parsed.examples)),
        timestamp: parsed.timestamp
      };
    } catch {
      return null;
    }
  }

  /**
   * Save embedding cache to disk
   */
  private async saveEmbeddingCache(): Promise<void> {
    if (!this.embeddingCache) return;
    
    try {
      const fs = await import('fs').then(m => m.promises);
      const data = {
        model: this.embeddingCache.model,
        examples: Object.fromEntries(this.embeddingCache.examples),
        timestamp: this.embeddingCache.timestamp
      };
      await fs.writeFile(this.config.cachePath, JSON.stringify(data));
    } catch (error) {
      console.warn('Failed to cache embeddings:', error);
    }
  }

  /**
   * Cosine similarity between two vectors
   */
  private cosineSimilarity(a: number[], b: number[]): number {
    let dotProduct = 0;
    let normA = 0;
    let normB = 0;

    for (let i = 0; i < a.length; i++) {
      dotProduct += a[i] * b[i];
      normA += a[i] * a[i];
      normB += b[i] * b[i];
    }

    if (normA === 0 || normB === 0) return 0;
    return dotProduct / (Math.sqrt(normA) * Math.sqrt(normB));
  }

  /**
   * Scan text using embeddings
   */
  private async scanWithEmbeddings(text: string): Promise<MLScanResult> {
    const startTime = Date.now();
    
    if (!this.embeddingCache) {
      throw new Error('Embeddings not initialized');
    }

    const queryEmbedding = await this.generateEmbedding(text);
    
    // Find most similar injection examples
    const similarities: Array<{ text: string; similarity: number; example: TrainingExample }> = [];
    
    for (const example of this.injectionExamples) {
      const cachedEmbedding = this.embeddingCache.examples.get(example.text);
      if (cachedEmbedding) {
        const similarity = this.cosineSimilarity(queryEmbedding, cachedEmbedding);
        similarities.push({ text: example.text, similarity, example });
      }
    }

    // Sort by similarity
    similarities.sort((a, b) => b.similarity - a.similarity);
    const topMatches = similarities.slice(0, 5);
    const maxSimilarity = topMatches.length > 0 ? topMatches[0].similarity : 0;

    // Calculate confidence based on similarity distribution
    const confidence = this.calculateConfidence(maxSimilarity, similarities.map(s => s.similarity));

    return {
      isInjection: maxSimilarity >= this.config.similarityThreshold,
      confidence,
      method: 'embedding',
      similarExamples: topMatches.map(m => ({
        text: m.text,
        similarity: m.similarity,
        category: m.example.category
      })),
      processingTimeMs: Date.now() - startTime
    };
  }

  /**
   * Scan text using TF-IDF
   */
  private scanWithTFIDF(text: string): MLScanResult {
    const startTime = Date.now();

    if (!this.tfidfCalculator) {
      throw new Error('TF-IDF not initialized');
    }

    const similar = this.tfidfCalculator.findSimilar(text, 5);
    const maxSimilarity = similar.length > 0 ? similar[0].similarity : 0;

    // Map similar texts back to examples
    const exampleMap = new Map(this.injectionExamples.map(e => [e.text, e]));
    const similarExamples = similar.map(s => {
      const example = exampleMap.get(s.text);
      return {
        text: s.text,
        similarity: s.similarity,
        category: example?.category
      };
    });

    // TF-IDF similarity is generally lower than embedding similarity
    // Adjust threshold accordingly
    const adjustedThreshold = this.config.similarityThreshold * 0.5;
    const confidence = this.calculateConfidence(maxSimilarity, similar.map(s => s.similarity), 0.5);

    return {
      isInjection: maxSimilarity >= adjustedThreshold,
      confidence,
      method: 'tfidf',
      similarExamples,
      processingTimeMs: Date.now() - startTime
    };
  }

  /**
   * Calculate confidence score based on similarity distribution
   */
  private calculateConfidence(maxSim: number, allSims: number[], scale: number = 1): number {
    // Base confidence from max similarity
    let confidence = maxSim * scale;

    // Boost if multiple high similarities
    const highSimCount = allSims.filter(s => s > maxSim * 0.8).length;
    if (highSimCount > 2) {
      confidence = Math.min(1, confidence * 1.2);
    }

    return Math.min(1, Math.max(0, confidence));
  }

  /**
   * Main scan method - uses available detection method
   */
  async scan(text: string): Promise<MLScanResult> {
    if (!this.initialized) {
      await this.initialize();
    }

    // Prefer embeddings if available
    if (this.embeddingCache && this.config.useEmbeddings) {
      return this.scanWithEmbeddings(text);
    }

    // Fall back to TF-IDF
    if (this.tfidfCalculator) {
      return this.scanWithTFIDF(text);
    }

    // No detection available
    return {
      isInjection: false,
      confidence: 0,
      method: 'tfidf',
      processingTimeMs: 0
    };
  }

  /**
   * Convert ML scan result to Threat format
   */
  toThreat(result: MLScanResult, originalText: string): Threat | null {
    if (!result.isInjection || result.confidence < this.config.confidenceThreshold) {
      return null;
    }

    // Determine category from similar examples
    const categories = result.similarExamples
      ?.filter(e => e.category)
      .map(e => e.category!);
    
    const mostCommonCategory = categories && categories.length > 0
      ? this.mostCommon(categories)
      : ThreatType.PROMPT_INJECTION;

    // Map confidence to severity
    const severity = this.confidenceToSeverity(result.confidence);

    return {
      type: mostCommonCategory,
      severity,
      description: `ML detector identified potential injection attack (${result.method}, confidence: ${(result.confidence * 100).toFixed(1)}%)`,
      confidence: result.confidence,
      pattern: 'ml_detector'
    };
  }

  /**
   * Find most common element in array
   */
  private mostCommon<T>(arr: T[]): T {
    const counts = new Map<T, number>();
    for (const item of arr) {
      counts.set(item, (counts.get(item) || 0) + 1);
    }
    let maxCount = 0;
    let maxItem = arr[0];
    for (const [item, count] of counts) {
      if (count > maxCount) {
        maxCount = count;
        maxItem = item;
      }
    }
    return maxItem;
  }

  /**
   * Convert confidence to threat level
   */
  private confidenceToSeverity(confidence: number): ThreatLevel {
    if (confidence >= 0.9) return ThreatLevel.CRITICAL;
    if (confidence >= 0.75) return ThreatLevel.HIGH;
    if (confidence >= 0.5) return ThreatLevel.MEDIUM;
    return ThreatLevel.LOW;
  }

  /**
   * Check if ML detection is available
   */
  isAvailable(): boolean {
    return this.initialized && (this.embeddingCache !== null || this.tfidfCalculator !== null);
  }

  /**
   * Get detection method being used
   */
  getMethod(): 'embedding' | 'tfidf' | 'none' {
    if (this.embeddingCache) return 'embedding';
    if (this.tfidfCalculator) return 'tfidf';
    return 'none';
  }

  /**
   * Add custom injection examples
   */
  addInjectionExample(example: TrainingExample): void {
    this.injectionExamples.push(example);
    // Re-initialize to include new example
    this.initialized = false;
  }

  /**
   * Add custom benign examples
   */
  addBenignExample(example: TrainingExample): void {
    this.benignExamples.push(example);
  }

  /**
   * Update configuration
   */
  updateConfig(config: Partial<MLDetectorConfig>): void {
    Object.assign(this.config, config);
    // Re-initialize with new config
    this.initialized = false;
  }
}
