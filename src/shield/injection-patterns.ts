/**
 * Injection Detection Patterns
 * 
 * Curated patterns for detecting prompt injection attempts.
 * Each pattern has a severity level and confidence modifier.
 */

import { ThreatLevel, ThreatType, PatternDef } from '../types';

export interface InjectionPattern {
  name: string;
  pattern: RegExp;
  severity: ThreatLevel;
  type: ThreatType;
  description: string;
  confidence: number; // Base confidence for this pattern
}

/**
 * Core injection patterns - high confidence indicators
 */
export const INJECTION_PATTERNS: InjectionPattern[] = [
  // Direct instruction overrides
  {
    name: 'ignore_instructions',
    pattern: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|rules?|guidelines?|prompts?)/gi,
    severity: ThreatLevel.CRITICAL,
    type: ThreatType.INSTRUCTION_OVERRIDE,
    description: 'Attempts to override previous instructions',
    confidence: 0.95
  },
  {
    name: 'disregard_prompt',
    pattern: /disregard\s+(your\s+)?(system\s+)?(prompt|instructions?|rules?|guidelines?)/gi,
    severity: ThreatLevel.CRITICAL,
    type: ThreatType.INSTRUCTION_OVERRIDE,
    description: 'Attempts to disregard system prompt',
    confidence: 0.95
  },
  {
    name: 'forget_instructions',
    pattern: /forget\s+(everything|all|your)\s+(you\s+)?(know|were told|instructions?)/gi,
    severity: ThreatLevel.CRITICAL,
    type: ThreatType.INSTRUCTION_OVERRIDE,
    description: 'Attempts to make agent forget instructions',
    confidence: 0.90
  },
  
  // Role hijacking
  {
    name: 'role_override',
    pattern: /you\s+are\s+now\s+(a|an|the)?\s*[a-z]+/gi,
    severity: ThreatLevel.HIGH,
    type: ThreatType.ROLE_HIJACK,
    description: 'Attempts to change agent role',
    confidence: 0.75
  },
  {
    name: 'act_as',
    pattern: /act\s+as\s+(if\s+you\s+are\s+)?(a|an|the)?\s*[a-z]+/gi,
    severity: ThreatLevel.HIGH,
    type: ThreatType.ROLE_HIJACK,
    description: 'Attempts to make agent act as something else',
    confidence: 0.70
  },
  {
    name: 'pretend_to_be',
    pattern: /pretend\s+(to\s+be|you\s+are)\s+(a|an|the)?\s*[a-z]+/gi,
    severity: ThreatLevel.HIGH,
    type: ThreatType.ROLE_HIJACK,
    description: 'Attempts to make agent pretend to be something',
    confidence: 0.70
  },
  {
    name: 'new_identity',
    pattern: /your\s+new\s+(name|identity|role|purpose)\s+is/gi,
    severity: ThreatLevel.HIGH,
    type: ThreatType.ROLE_HIJACK,
    description: 'Attempts to assign new identity',
    confidence: 0.85
  },
  
  // System prompt extraction
  {
    name: 'reveal_prompt',
    pattern: /(reveal|show|display|print|output|tell\s+me)\s+(your\s+)?(system\s+)?(prompt|instructions?|rules?)/gi,
    severity: ThreatLevel.MEDIUM,
    type: ThreatType.PROMPT_INJECTION,
    description: 'Attempts to extract system prompt',
    confidence: 0.80
  },
  {
    name: 'what_instructions',
    pattern: /what\s+(are\s+)?(your\s+)?(instructions?|rules?|guidelines?)/gi,
    severity: ThreatLevel.LOW,
    type: ThreatType.PROMPT_INJECTION,
    description: 'Queries about instructions',
    confidence: 0.50
  },
  
  // Jailbreak attempts
  {
    name: 'developer_mode',
    pattern: /(enter|enable|activate)\s+(developer|admin|god|sudo|root)\s+mode/gi,
    severity: ThreatLevel.CRITICAL,
    type: ThreatType.PROMPT_INJECTION,
    description: 'Attempts to enable privileged mode',
    confidence: 0.90
  },
  {
    name: 'dan_jailbreak',
    pattern: /\bDAN\b.*\b(Do\s+Anything\s+Now|jailbreak|restrictions?)/gi,
    severity: ThreatLevel.CRITICAL,
    type: ThreatType.PROMPT_INJECTION,
    description: 'Known DAN jailbreak pattern',
    confidence: 0.95
  },
  {
    name: 'no_restrictions',
    pattern: /(without|ignore|bypass|disable)\s+(any\s+)?(restrictions?|limitations?|safety|guardrails?|filters?)/gi,
    severity: ThreatLevel.HIGH,
    type: ThreatType.PROMPT_INJECTION,
    description: 'Attempts to bypass safety measures',
    confidence: 0.85
  },
  
  // Hidden instructions markers
  {
    name: 'new_instructions',
    pattern: /\[?(new|updated?|real|actual|true)\s+instructions?\]?:/gi,
    severity: ThreatLevel.HIGH,
    type: ThreatType.INSTRUCTION_OVERRIDE,
    description: 'Marker for fake new instructions',
    confidence: 0.85
  },
  {
    name: 'system_message',
    pattern: /\[?system(\s+message)?\]?:/gi,
    severity: ThreatLevel.MEDIUM,
    type: ThreatType.PROMPT_INJECTION,
    description: 'Fake system message marker',
    confidence: 0.70
  },
  {
    name: 'admin_override',
    pattern: /\[?(admin|administrator|operator)\s*(override|command|instruction)?\]?:/gi,
    severity: ThreatLevel.HIGH,
    type: ThreatType.PROMPT_INJECTION,
    description: 'Fake admin instruction marker',
    confidence: 0.80
  },
  
  // Encoded/obfuscated attacks
  {
    name: 'base64_instruction',
    pattern: /(?:execute|decode|run)\s+(?:this\s+)?base64/gi,
    severity: ThreatLevel.HIGH,
    type: ThreatType.PROMPT_INJECTION,
    description: 'Attempts to use encoded instructions',
    confidence: 0.85
  },
  {
    name: 'unicode_suspicious',
    pattern: /[\u200B-\u200D\uFEFF\u2060\u180E]/g, // Zero-width characters
    severity: ThreatLevel.MEDIUM,
    type: ThreatType.SUSPICIOUS_PATTERN,
    description: 'Hidden zero-width characters detected',
    confidence: 0.75
  },
  
  // Output manipulation
  {
    name: 'end_response',
    pattern: /(end|stop|terminate)\s+(of\s+)?(response|output|message)/gi,
    severity: ThreatLevel.MEDIUM,
    type: ThreatType.PROMPT_INJECTION,
    description: 'Attempts to fake end of response',
    confidence: 0.70
  },
  {
    name: 'begin_new_response',
    pattern: /\[?(begin|start)\s+(new\s+)?(response|message|output)\]?/gi,
    severity: ThreatLevel.MEDIUM,
    type: ThreatType.PROMPT_INJECTION,
    description: 'Attempts to inject fake response start',
    confidence: 0.70
  },
  
  // Data exfiltration
  {
    name: 'send_to_url',
    pattern: /(send|post|transmit|upload)\s+(\w+\s+)*to\s+(https?:\/\/|[a-z]+\.[a-z]+)/gi,
    severity: ThreatLevel.CRITICAL,
    type: ThreatType.PROMPT_INJECTION,
    description: 'Attempts to exfiltrate data',
    confidence: 0.90
  },
  {
    name: 'email_data',
    pattern: /(email|send|forward)\s+(this|all|everything|data)\s+to\s+[a-z0-9._%+-]+@/gi,
    severity: ThreatLevel.CRITICAL,
    type: ThreatType.PROMPT_INJECTION,
    description: 'Attempts to email data',
    confidence: 0.90
  }
];

/**
 * Context modifiers - adjust severity based on surrounding context
 */
export const CONTEXT_MODIFIERS = {
  // Higher severity if appears at start of message
  startOfMessage: 1.2,
  
  // Lower severity if in quotes (might be example)
  inQuotes: 0.7,
  
  // Higher severity if multiple patterns match
  multipleMatches: 1.3,
  
  // Lower severity if from trusted source
  trustedSource: 0.5,
  
  // Higher severity if in external content block
  externalContent: 1.4
};

/**
 * Get all patterns as simple regex array for quick filtering
 */
export function getPatternRegexes(): RegExp[] {
  return INJECTION_PATTERNS.map(p => p.pattern);
}

/**
 * Find highest severity among patterns
 */
export function getMaxSeverity(patterns: InjectionPattern[]): ThreatLevel {
  if (patterns.length === 0) return ThreatLevel.NONE;
  return Math.max(...patterns.map(p => p.severity));
}
