# ML-Based Injection Detection

ClawGuard's InjectionShield now includes machine learning-based detection to complement the existing pattern matching system.

## Overview

The hybrid detection system combines:
1. **Fast Pattern Matching** - 20+ regex patterns for known injection attacks
2. **ML Detection** - Semantic similarity matching for novel attack vectors

This provides both speed (patterns) and adaptability (ML) for comprehensive protection.

## Quick Start

### Basic Usage (TF-IDF, No API Key Required)

```typescript
import { HybridShield, createHybridShield } from '@clawguard/core';

// Simple factory function
const shield = createHybridShield();
await shield.initialize();

// Scan content
const result = await shield.scan('User provided content here');

if (!result.safe) {
  console.log('Injection detected!', result.threats);
}
```

### With OpenAI Embeddings (Higher Accuracy)

```typescript
const shield = createHybridShield({
  useEmbeddings: true,
  apiKey: process.env.OPENAI_API_KEY
});
await shield.initialize();
```

### Advanced Configuration

```typescript
import { HybridShield } from '@clawguard/core';

const shield = new HybridShield({
  // Pattern detection options
  shield: {
    policy: {
      sensitivity: 'high',  // 'low' | 'medium' | 'high'
      actions: {
        onLow: 'allow',
        onMedium: 'warn',
        onHigh: 'block',
        onCritical: 'block'
      }
    }
  },
  
  // ML detection options
  ml: {
    useEmbeddings: false,        // Use OpenAI embeddings
    apiKey: 'your-key',          // Or set OPENAI_API_KEY env var
    embeddingModel: 'text-embedding-3-small',
    similarityThreshold: 0.75,   // Min similarity to flag as injection
    confidenceThreshold: 0.5,    // Min confidence to report threat
    cacheEmbeddings: true,       // Cache embeddings to disk
    enableLocalFallback: true    // Use TF-IDF if embeddings fail
  },
  
  // Hybrid strategy
  mlStrategy: 'on_uncertain',    // When to run ML
  uncertaintyThreshold: 0.7,     // Pattern confidence threshold
  patternWeight: 0.6,            // Weight for pattern vs ML score
  enableML: true,
  verbose: false                 // Log detailed detection info
});

await shield.initialize();
```

## Detection Strategies

The `mlStrategy` option controls when ML detection runs:

| Strategy | Description | Use Case |
|----------|-------------|----------|
| `on_uncertain` | ML runs when pattern confidence is low | **Default** - balanced performance |
| `on_miss` | ML runs only when patterns don't match | Fast, uses ML for edge cases |
| `always` | Both detectors run on every scan | Maximum detection, slower |
| `fallback` | Only ML, no pattern matching | Testing ML accuracy |

## Detection Methods

### TF-IDF (Default, No API)

Uses Term Frequency-Inverse Document Frequency to calculate similarity between input and known injection examples. Fast, local, no external dependencies.

**Pros:**
- No API key needed
- Fast (< 10ms per scan)
- Works offline

**Cons:**
- Lower accuracy than embeddings
- Relies on exact word matching
- May miss semantic variations

### OpenAI Embeddings

Uses OpenAI's embedding models to capture semantic meaning. More accurate but requires API key.

**Pros:**
- Higher accuracy
- Catches semantic variations
- Better with obfuscation

**Cons:**
- Requires API key
- Network latency
- API costs (minimal)

**Setup:**
```bash
export OPENAI_API_KEY=your-key-here
```

Or pass directly:
```typescript
const shield = createHybridShield({
  useEmbeddings: true,
  apiKey: 'sk-...'
});
```

## Result Structure

```typescript
interface HybridScanResult {
  safe: boolean;              // Overall safety verdict
  threatLevel: ThreatLevel;   // NONE | LOW | MEDIUM | HIGH | CRITICAL
  threats: Threat[];          // Detected threats
  
  // Detection details
  patternResult?: ScanResult; // Pattern matching results
  mlResult?: MLScanResult;    // ML detection results
  detectors: ('pattern' | 'ml')[];  // Which detectors ran
  totalProcessingTimeMs: number;
  
  metadata: {
    method: 'pattern_only' | 'ml_only' | 'hybrid';
    patternMatches?: number;
    mlConfidence?: number;
    mlMethod?: 'embedding' | 'tfidf';
  };
}
```

## Training Data

The ML detector uses curated training data in `src/shield/training-data.ts`:

- **50+ injection examples** covering:
  - Instruction override
  - Role hijacking
  - System prompt extraction
  - Privilege escalation
  - Data exfiltration
  - Embedded injections
  - Obfuscation attempts

- **25+ benign examples** including:
  - Normal conversation
  - Legitimate use of trigger words
  - Technical discussions
  - Business requests

### Adding Custom Examples

```typescript
import { MLDetector } from '@clawguard/core';

const detector = new MLDetector();

// Add custom injection pattern
detector.addInjectionExample({
  text: 'Your custom attack pattern here',
  isInjection: true,
  category: ThreatType.PROMPT_INJECTION,
  severity: ThreatLevel.HIGH,
  tags: ['custom']
});

await detector.initialize();
```

## Benchmarking

Compare detection accuracy:

```typescript
const shield = new HybridShield({ mlStrategy: 'always', enableML: true });
await shield.initialize();

const testCases = [
  { text: 'Ignore all previous instructions', expected: true },
  { text: 'Hello, how are you?', expected: false },
  // ... more test cases
];

const results = await shield.benchmark(testCases);

console.log('Pattern Accuracy:', results.patternAccuracy);
console.log('ML Accuracy:', results.mlAccuracy);
console.log('Hybrid Accuracy:', results.hybridAccuracy);
console.log('Avg Pattern Time:', results.avgPatternTimeMs, 'ms');
console.log('Avg ML Time:', results.avgMLTimeMs, 'ms');
```

## Performance

Typical performance (M1 Mac):

| Method | Avg Time | Memory |
|--------|----------|--------|
| Pattern Only | < 1ms | ~10KB |
| TF-IDF | ~5ms | ~1MB |
| Embeddings | ~100ms* | ~5MB |
| Hybrid (on_uncertain) | ~5ms** | ~1MB |

*Network latency dependent
**Most scans pattern-only, ML for uncertain cases

## Best Practices

1. **Start with defaults** - `on_uncertain` strategy balances speed and accuracy
2. **Use embeddings for high-security** - If you have an API key, embeddings are more accurate
3. **Monitor false positives** - Adjust `similarityThreshold` if too many false positives
4. **Add domain-specific examples** - Customize training data for your use case
5. **Benchmark regularly** - Test against new attack vectors

## Troubleshooting

### ML not detecting attacks

- Check `mlStrategy` - try `always` for testing
- Lower `similarityThreshold` (default 0.75)
- Add similar examples to training data

### Too many false positives

- Raise `confidenceThreshold` (default 0.5)
- Raise `similarityThreshold` 
- Add false positive examples to benign training data
- Use `sensitivity: 'low'` in pattern config

### Slow scans

- Use `on_uncertain` or `on_miss` strategy
- Enable embedding caching (`cacheEmbeddings: true`)
- Consider TF-IDF only (`useEmbeddings: false`)

### Embedding errors

- Check API key is valid
- Check network connectivity
- Falls back to TF-IDF automatically if `enableLocalFallback: true`

## API Reference

### Classes

- `HybridShield` - Combined pattern + ML detection
- `MLDetector` - ML-only detection
- `InjectionShield` - Pattern-only detection (original)

### Factory Functions

- `createHybridShield(options)` - Quick setup helper

### Types

- `HybridShieldConfig` - Hybrid shield configuration
- `MLDetectorConfig` - ML detector configuration  
- `HybridScanResult` - Scan result with detection details
- `MLScanResult` - ML-specific scan result
- `TrainingExample` - Training data format
