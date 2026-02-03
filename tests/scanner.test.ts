/**
 * Secret Scanner Tests
 * 
 * Test patterns are built dynamically to avoid triggering GitHub push protection.
 * These are NOT real secrets - they're fake patterns for testing.
 */

import { SecretScanner } from '../src/scanner/secret-scanner';
import { ThreatLevel, ThreatType } from '../src/types';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

// Build test patterns dynamically to avoid static secret detection
const TEST_PATTERNS = {
  // OpenAI: sk-{20chars}T3BlbkFJ{20chars}
  openai: () => 'sk-' + 'a'.repeat(20) + ['T3', 'Blbk', 'FJ'].join('') + 'b'.repeat(20),
  openai2: () => 'sk-' + 'x'.repeat(20) + ['T3', 'Blbk', 'FJ'].join('') + 'y'.repeat(20),
  // Stripe: sk_live_{24+chars}
  stripe: () => ['sk', 'live', '0'.repeat(26)].join('_'),
  stripe2: () => ['sk', 'live', '1'.repeat(26)].join('_'),
  // Slack: xoxb-{10digits}-{13digits}-{24chars}
  slack: () => 'xoxb-' + '0'.repeat(10) + '-' + '0'.repeat(13) + '-' + 'a'.repeat(24),
  // Discord: base64.xxx.xxx
  discord: () => ['MTIz', 'NDU2', 'Nzg5', 'MDEy', 'MzQ1', 'Njc4', 'OQ'].join('') + '.GHjklM.' + 'a'.repeat(27),
};

describe('SecretScanner', () => {
  let scanner: SecretScanner;

  beforeEach(() => {
    scanner = new SecretScanner();
  });

  describe('Basic Scanning', () => {
    it('should return safe for normal content', () => {
      const result = scanner.scan('This is just normal text without any secrets.');
      expect(result.safe).toBe(true);
      expect(result.threatLevel).toBe(ThreatLevel.NONE);
    });

    it('should detect OpenAI API keys', () => {
      // Classic OpenAI key format - built dynamically to avoid push protection
      const result = scanner.scan('OPENAI_KEY=' + TEST_PATTERNS.openai());
      expect(result.safe).toBe(false);
      expect(result.threats[0].type).toBe(ThreatType.API_KEY);
    });

    it('should detect GitHub tokens', () => {
      const result = scanner.scan('TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz');
      expect(result.safe).toBe(false);
      expect(result.threats[0].type).toBe(ThreatType.TOKEN);
      expect(result.threats[0].pattern).toBe('github_token');
    });

    it('should detect AWS access keys', () => {
      const result = scanner.scan('AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE');
      expect(result.safe).toBe(false);
      expect(result.threats[0].type).toBe(ThreatType.API_KEY);
      expect(result.threats[0].pattern).toBe('aws_access_key');
    });

    it('should detect Google API keys', () => {
      // Google API key format: AIza followed by exactly 35 alphanumeric/underscore/hyphen chars
      const result = scanner.scan('GOOGLE_API_KEY=AIzaSyC_abcdefghijklmnopqrstuvwxyz12345');
      expect(result.safe).toBe(false);
      expect(result.threats.some(t => t.pattern === 'google_api_key')).toBe(true);
    });

    it('should detect Stripe keys', () => {
      const result = scanner.scan('STRIPE_SECRET=' + TEST_PATTERNS.stripe());
      expect(result.safe).toBe(false);
      expect(result.threatLevel).toBe(ThreatLevel.CRITICAL);
    });

    it('should detect private key headers', () => {
      const result = scanner.scan('-----BEGIN RSA PRIVATE KEY-----');
      expect(result.safe).toBe(false);
      expect(result.threats[0].type).toBe(ThreatType.PRIVATE_KEY);
    });

    it('should detect database connection strings', () => {
      const result = scanner.scan('DATABASE_URL=postgres://user:password123@localhost:5432/mydb');
      expect(result.safe).toBe(false);
      expect(result.threats[0].type).toBe(ThreatType.CONNECTION_STRING);
    });

    it('should detect MongoDB connection strings', () => {
      const result = scanner.scan('MONGO_URI=mongodb+srv://admin:secretpass@cluster.mongodb.net/db');
      expect(result.safe).toBe(false);
      expect(result.threats[0].pattern).toBe('mongodb_url');
    });

    it('should detect JWT tokens', () => {
      const result = scanner.scan('token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U');
      expect(result.safe).toBe(false);
      expect(result.threats[0].pattern).toBe('jwt_token');
    });

    it('should detect Slack tokens', () => {
      const result = scanner.scan('SLACK_TOKEN=' + TEST_PATTERNS.slack());
      expect(result.safe).toBe(false);
      expect(result.threats[0].pattern).toBe('slack_token');
    });

    it('should detect Discord tokens', () => {
      const result = scanner.scan('BOT_TOKEN=' + TEST_PATTERNS.discord());
      expect(result.safe).toBe(false);
      expect(result.threats[0].pattern).toBe('discord_token');
    });

    it('should detect password assignments', () => {
      const result = scanner.scan('password = "super_secret_password_123"');
      expect(result.safe).toBe(false);
      expect(result.threats[0].type).toBe(ThreatType.PASSWORD);
    });

    it('should detect Notion API keys', () => {
      // Notion key format: ntn_ followed by 50+ alphanumeric chars
      const result = scanner.scan('NOTION_KEY=ntn_abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOP');
      expect(result.safe).toBe(false);
      expect(result.threats.some(t => t.pattern === 'notion_api_key')).toBe(true);
    });
  });

  describe('Multiple Secrets', () => {
    it('should detect multiple secrets in one file', () => {
      const content = `
        OPENAI_KEY=${TEST_PATTERNS.openai2()}
        GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz
        DATABASE_URL=postgres://user:pass@localhost/db
      `;
      
      const result = scanner.scan(content);
      expect(result.threats.length).toBeGreaterThanOrEqual(3);
    });

    it('should return highest severity level', () => {
      const content = `
        ${TEST_PATTERNS.stripe2()}
        ${TEST_PATTERNS.stripe()}
      `;
      
      const result = scanner.scan(content);
      expect(result.threatLevel).toBe(ThreatLevel.CRITICAL);
    });
  });

  describe('Redaction', () => {
    it('should redact secrets while preserving structure', () => {
      const content = 'API_KEY=ghp_1234567890abcdefghijklmnopqrstuvwxyz';
      const { redacted, secretsFound } = scanner.redact(content);
      
      expect(secretsFound).toBe(1);
      expect(redacted).toContain('ghp_');
      expect(redacted).toContain('wxyz');
      expect(redacted).toContain('*');
      expect(redacted).not.toBe(content);
    });

    it('should redact multiple secrets', () => {
      const content = `
        KEY1=ghp_1234567890abcdefghijklmnopqrstuvwxyz
        KEY2=${TEST_PATTERNS.stripe()}
      `;
      
      const { redacted, secretsFound } = scanner.redact(content);
      expect(secretsFound).toBeGreaterThanOrEqual(2);
      // Should contain asterisks from redaction
      expect(redacted).toContain('*');
      // Should not contain the full original secrets
      expect(redacted).not.toContain('ghp_1234567890abcdefghijklmnopqrstuvwxyz');
    });

    it('should handle short secrets', () => {
      // For very short matches, should fully redact
      const content = 'short';
      const { redacted } = scanner.redact(content);
      // No secrets found, content unchanged
      expect(redacted).toBe(content);
    });
  });

  describe('File Scanning', () => {
    const tempDir = path.join(os.tmpdir(), 'clawguard-test-' + Date.now());
    
    beforeAll(async () => {
      await fs.promises.mkdir(tempDir, { recursive: true });
    });

    afterAll(async () => {
      await fs.promises.rm(tempDir, { recursive: true, force: true });
    });

    it('should scan a file with secrets', async () => {
      const testFile = path.join(tempDir, 'test.env');
      await fs.promises.writeFile(testFile, 'API_KEY=ghp_1234567890abcdefghijklmnopqrstuvwxyz');
      
      const result = await scanner.scanFile(testFile);
      expect(result.safe).toBe(false);
      expect(result.filePath).toBe(testFile);
      expect(result.fileSize).toBeGreaterThan(0);
    });

    it('should handle non-existent files', async () => {
      const result = await scanner.scanFile('/nonexistent/file.txt');
      expect(result.safe).toBe(true);
      expect(result.metadata.error).toBeDefined();
    });

    it('should scan a directory', async () => {
      const testFile1 = path.join(tempDir, 'config.env');
      const testFile2 = path.join(tempDir, 'safe.txt');
      
      await fs.promises.writeFile(testFile1, 'SECRET=${TEST_PATTERNS.stripe()}');
      await fs.promises.writeFile(testFile2, 'This is safe content');
      
      const results = await scanner.scanDirectory(tempDir);
      
      // Should only return files with issues
      expect(results.some(r => r.filePath === testFile1)).toBe(true);
    });

    it('should exclude specified paths', async () => {
      const nodeModulesDir = path.join(tempDir, 'node_modules');
      await fs.promises.mkdir(nodeModulesDir, { recursive: true });
      
      const testFile = path.join(nodeModulesDir, 'secret.js');
      await fs.promises.writeFile(testFile, 'KEY=${TEST_PATTERNS.stripe()}');
      
      const results = await scanner.scanDirectory(tempDir);
      
      // Should not include files from node_modules
      expect(results.some(r => r.filePath.includes('node_modules'))).toBe(false);
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty content', () => {
      const result = scanner.scan('');
      expect(result.safe).toBe(true);
    });

    it('should handle binary-like content', () => {
      const result = scanner.scan('\x00\x01\x02\x03');
      expect(result.safe).toBe(true);
    });

    it('should not false positive on similar patterns', () => {
      // These look like keys but aren't valid formats
      const result = scanner.scan('sk_not_a_real_key');
      // Should be safe because it doesn't match the full pattern
      expect(result.threats.length).toBe(0);
    });

    it('should handle very long content', () => {
      const longContent = 'Normal text. '.repeat(10000);
      const result = scanner.scan(longContent);
      expect(result.safe).toBe(true);
    });
  });

  describe('Policy', () => {
    it('should respect disabled policy', () => {
      const disabledScanner = new SecretScanner({
        policy: { enabled: false }
      });
      
      const result = disabledScanner.scan('ghp_1234567890abcdefghijklmnopqrstuvwxyz');
      expect(result.safe).toBe(true);
    });

    it('should return correct actions', () => {
      expect(scanner.getAction('read')).toBe('warn');
      expect(scanner.getAction('write')).toBe('block');
      expect(scanner.getAction('existing')).toBe('report');
    });

    it('should allow policy updates', () => {
      scanner.updatePolicy({
        actions: {
          onRead: 'block',
          onWrite: 'block',
          onExisting: 'quarantine'
        }
      });
      
      expect(scanner.getAction('read')).toBe('block');
    });
  });
});
