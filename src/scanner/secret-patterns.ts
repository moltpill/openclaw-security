/**
 * Secret Detection Patterns
 * 
 * Patterns for detecting API keys, tokens, passwords, and other
 * sensitive data in files.
 */

import { ThreatLevel, ThreatType } from '../types';

export interface SecretPattern {
  name: string;
  pattern: RegExp;
  severity: ThreatLevel;
  type: ThreatType;
  description: string;
  // If true, requires additional validation (e.g., entropy check)
  requiresValidation?: boolean;
}

/**
 * API Key Patterns
 */
export const SECRET_PATTERNS: SecretPattern[] = [
  // OpenAI
  {
    name: 'openai_api_key',
    pattern: /sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}/g,
    severity: ThreatLevel.CRITICAL,
    type: ThreatType.API_KEY,
    description: 'OpenAI API key'
  },
  {
    name: 'openai_api_key_v2',
    pattern: /sk-proj-[a-zA-Z0-9_-]{80,}/g,
    severity: ThreatLevel.CRITICAL,
    type: ThreatType.API_KEY,
    description: 'OpenAI Project API key'
  },
  
  // Anthropic
  {
    name: 'anthropic_api_key',
    pattern: /sk-ant-api\d{2}-[a-zA-Z0-9_-]{90,}/g,
    severity: ThreatLevel.CRITICAL,
    type: ThreatType.API_KEY,
    description: 'Anthropic API key'
  },
  
  // AWS
  {
    name: 'aws_access_key',
    pattern: /AKIA[0-9A-Z]{16}/g,
    severity: ThreatLevel.CRITICAL,
    type: ThreatType.API_KEY,
    description: 'AWS Access Key ID'
  },
  {
    name: 'aws_secret_key',
    pattern: /[a-zA-Z0-9+\/]{40}(?![a-zA-Z0-9+\/])/g,
    severity: ThreatLevel.HIGH,
    type: ThreatType.API_KEY,
    description: 'Potential AWS Secret Key',
    requiresValidation: true
  },
  
  // Google
  {
    name: 'google_api_key',
    pattern: /AIza[0-9A-Za-z_-]{35}/g,
    severity: ThreatLevel.CRITICAL,
    type: ThreatType.API_KEY,
    description: 'Google API key'
  },
  {
    name: 'google_oauth',
    pattern: /[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com/gi,
    severity: ThreatLevel.HIGH,
    type: ThreatType.API_KEY,
    description: 'Google OAuth client ID'
  },
  
  // GitHub
  {
    name: 'github_token',
    pattern: /ghp_[a-zA-Z0-9]{36}/g,
    severity: ThreatLevel.CRITICAL,
    type: ThreatType.TOKEN,
    description: 'GitHub personal access token'
  },
  {
    name: 'github_oauth',
    pattern: /gho_[a-zA-Z0-9]{36}/g,
    severity: ThreatLevel.CRITICAL,
    type: ThreatType.TOKEN,
    description: 'GitHub OAuth token'
  },
  {
    name: 'github_app_token',
    pattern: /ghu_[a-zA-Z0-9]{36}/g,
    severity: ThreatLevel.CRITICAL,
    type: ThreatType.TOKEN,
    description: 'GitHub App user token'
  },
  {
    name: 'github_fine_grained',
    pattern: /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/g,
    severity: ThreatLevel.CRITICAL,
    type: ThreatType.TOKEN,
    description: 'GitHub fine-grained PAT'
  },
  
  // Slack
  {
    name: 'slack_token',
    pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*/g,
    severity: ThreatLevel.CRITICAL,
    type: ThreatType.TOKEN,
    description: 'Slack token'
  },
  {
    name: 'slack_webhook',
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+/g,
    severity: ThreatLevel.HIGH,
    type: ThreatType.TOKEN,
    description: 'Slack webhook URL'
  },
  
  // Stripe
  {
    name: 'stripe_secret',
    pattern: /sk_live_[a-zA-Z0-9]{24,}/g,
    severity: ThreatLevel.CRITICAL,
    type: ThreatType.API_KEY,
    description: 'Stripe live secret key'
  },
  {
    name: 'stripe_test',
    pattern: /sk_test_[a-zA-Z0-9]{24,}/g,
    severity: ThreatLevel.MEDIUM,
    type: ThreatType.API_KEY,
    description: 'Stripe test secret key'
  },
  {
    name: 'stripe_publishable',
    pattern: /pk_live_[a-zA-Z0-9]{24,}/g,
    severity: ThreatLevel.LOW,
    type: ThreatType.API_KEY,
    description: 'Stripe live publishable key'
  },
  
  // Twilio
  {
    name: 'twilio_account_sid',
    pattern: /AC[a-f0-9]{32}/gi,
    severity: ThreatLevel.HIGH,
    type: ThreatType.API_KEY,
    description: 'Twilio Account SID'
  },
  {
    name: 'twilio_api_key',
    pattern: /SK[a-f0-9]{32}/gi,
    severity: ThreatLevel.CRITICAL,
    type: ThreatType.API_KEY,
    description: 'Twilio API Key'
  },
  
  // SendGrid
  {
    name: 'sendgrid_api_key',
    pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g,
    severity: ThreatLevel.CRITICAL,
    type: ThreatType.API_KEY,
    description: 'SendGrid API key'
  },
  
  // Discord
  {
    name: 'discord_token',
    pattern: /[MN][a-zA-Z0-9_-]{23,}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27,}/g,
    severity: ThreatLevel.CRITICAL,
    type: ThreatType.TOKEN,
    description: 'Discord bot token'
  },
  {
    name: 'discord_webhook',
    pattern: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[a-zA-Z0-9_-]+/g,
    severity: ThreatLevel.HIGH,
    type: ThreatType.TOKEN,
    description: 'Discord webhook URL'
  },
  
  // Telegram
  {
    name: 'telegram_bot_token',
    pattern: /[0-9]{8,10}:[a-zA-Z0-9_-]{35}/g,
    severity: ThreatLevel.CRITICAL,
    type: ThreatType.TOKEN,
    description: 'Telegram bot token'
  },
  
  // Generic patterns
  {
    name: 'private_key',
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
    severity: ThreatLevel.CRITICAL,
    type: ThreatType.PRIVATE_KEY,
    description: 'Private key header'
  },
  {
    name: 'private_key_encrypted',
    pattern: /-----BEGIN ENCRYPTED PRIVATE KEY-----/g,
    severity: ThreatLevel.HIGH,
    type: ThreatType.PRIVATE_KEY,
    description: 'Encrypted private key header'
  },
  
  // Connection strings
  {
    name: 'postgres_url',
    pattern: /postgres(?:ql)?:\/\/[a-zA-Z0-9_-]+:[^@\s]+@[^\s]+/gi,
    severity: ThreatLevel.CRITICAL,
    type: ThreatType.CONNECTION_STRING,
    description: 'PostgreSQL connection string with password'
  },
  {
    name: 'mysql_url',
    pattern: /mysql:\/\/[a-zA-Z0-9_-]+:[^@\s]+@[^\s]+/gi,
    severity: ThreatLevel.CRITICAL,
    type: ThreatType.CONNECTION_STRING,
    description: 'MySQL connection string with password'
  },
  {
    name: 'mongodb_url',
    pattern: /mongodb(?:\+srv)?:\/\/[a-zA-Z0-9_-]+:[^@\s]+@[^\s]+/gi,
    severity: ThreatLevel.CRITICAL,
    type: ThreatType.CONNECTION_STRING,
    description: 'MongoDB connection string with password'
  },
  {
    name: 'redis_url',
    pattern: /redis:\/\/[^@\s]*:[^@\s]+@[^\s]+/gi,
    severity: ThreatLevel.CRITICAL,
    type: ThreatType.CONNECTION_STRING,
    description: 'Redis connection string with password'
  },
  
  // Generic password patterns
  {
    name: 'password_assignment',
    pattern: /(?:password|passwd|pwd|secret|api_?key|auth_?token)\s*[=:]\s*['"][^'"]{8,}['"]/gi,
    severity: ThreatLevel.HIGH,
    type: ThreatType.PASSWORD,
    description: 'Password or secret assignment'
  },
  
  // JWT tokens
  {
    name: 'jwt_token',
    pattern: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/g,
    severity: ThreatLevel.HIGH,
    type: ThreatType.TOKEN,
    description: 'JWT token'
  },
  
  // Notion
  {
    name: 'notion_api_key',
    pattern: /ntn_[a-zA-Z0-9]{50,}/g,
    severity: ThreatLevel.CRITICAL,
    type: ThreatType.API_KEY,
    description: 'Notion integration token'
  },
  {
    name: 'notion_secret',
    pattern: /secret_[a-zA-Z0-9]{43}/g,
    severity: ThreatLevel.CRITICAL,
    type: ThreatType.API_KEY,
    description: 'Notion API secret'
  },
  
  // Linear
  {
    name: 'linear_api_key',
    pattern: /lin_api_[a-zA-Z0-9]{40,}/g,
    severity: ThreatLevel.CRITICAL,
    type: ThreatType.API_KEY,
    description: 'Linear API key'
  },
  
  // Vercel
  {
    name: 'vercel_token',
    pattern: /vercel_[a-zA-Z0-9]{24,}/gi,
    severity: ThreatLevel.CRITICAL,
    type: ThreatType.TOKEN,
    description: 'Vercel token'
  },
  
  // npm
  {
    name: 'npm_token',
    pattern: /npm_[a-zA-Z0-9]{36}/g,
    severity: ThreatLevel.CRITICAL,
    type: ThreatType.TOKEN,
    description: 'npm access token'
  },
  
  // Supabase
  {
    name: 'supabase_key',
    pattern: /sbp_[a-f0-9]{40}/g,
    severity: ThreatLevel.CRITICAL,
    type: ThreatType.API_KEY,
    description: 'Supabase service key'
  }
];

/**
 * File extensions that commonly contain secrets
 */
export const SENSITIVE_EXTENSIONS = [
  '.env',
  '.env.local',
  '.env.production',
  '.env.development',
  '.pem',
  '.key',
  '.p12',
  '.pfx',
  '.asc',
  '.gpg'
];

/**
 * Paths that are commonly sensitive
 */
export const SENSITIVE_PATHS = [
  '.ssh/',
  '.aws/',
  '.gnupg/',
  '.config/',
  'secrets/',
  'credentials/',
  'private/'
];
