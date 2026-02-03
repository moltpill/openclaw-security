/**
 * Policy Engine Tests
 */

import { PolicyEngine, generateSamplePolicy } from '../src/policy/policy-engine';
import { ThreatLevel } from '../src/types';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

describe('PolicyEngine', () => {
  let engine: PolicyEngine;

  beforeEach(() => {
    engine = new PolicyEngine();
  });

  describe('Default Configuration', () => {
    it('should have shield enabled by default', () => {
      const shield = engine.getShieldPolicy();
      expect(shield?.enabled).toBe(true);
    });

    it('should have scanner enabled by default', () => {
      const scanner = engine.getScannerPolicy();
      expect(scanner?.enabled).toBe(true);
    });

    it('should have enclave enabled by default', () => {
      const enclave = engine.getEnclavePolicy();
      expect(enclave?.enabled).toBe(true);
    });

    it('should have audit enabled by default', () => {
      const audit = engine.getAuditPolicy();
      expect(audit?.enabled).toBe(true);
    });

    it('should have medium sensitivity by default', () => {
      const shield = engine.getShieldPolicy();
      expect(shield?.sensitivity).toBe('medium');
    });
  });

  describe('Shield Evaluation', () => {
    it('should allow on no threat', () => {
      const decision = engine.evaluateShield(ThreatLevel.NONE);
      expect(decision.action).toBe('allow');
    });

    it('should allow on low threat by default', () => {
      const decision = engine.evaluateShield(ThreatLevel.LOW);
      expect(decision.action).toBe('allow');
    });

    it('should warn on medium threat by default', () => {
      const decision = engine.evaluateShield(ThreatLevel.MEDIUM);
      expect(decision.action).toBe('warn');
    });

    it('should block on high threat by default', () => {
      const decision = engine.evaluateShield(ThreatLevel.HIGH);
      expect(decision.action).toBe('block');
    });

    it('should block on critical threat by default', () => {
      const decision = engine.evaluateShield(ThreatLevel.CRITICAL);
      expect(decision.action).toBe('block');
    });

    it('should include metadata in decision', () => {
      const decision = engine.evaluateShield(ThreatLevel.MEDIUM);
      expect(decision.metadata?.threatLevel).toBe(ThreatLevel.MEDIUM);
      expect(decision.metadata?.sensitivity).toBe('medium');
    });

    it('should allow all when disabled', () => {
      engine.updateConfig({ shield: { enabled: false } as any });
      const decision = engine.evaluateShield(ThreatLevel.CRITICAL);
      expect(decision.action).toBe('allow');
    });
  });

  describe('Scanner Evaluation', () => {
    it('should allow read without secrets', () => {
      const decision = engine.evaluateScanner('read', false);
      expect(decision.action).toBe('allow');
    });

    it('should warn on read with secrets by default', () => {
      const decision = engine.evaluateScanner('read', true);
      expect(decision.action).toBe('warn');
    });

    it('should block on write with secrets by default', () => {
      const decision = engine.evaluateScanner('write', true);
      expect(decision.action).toBe('block');
    });

    it('should warn on existing secrets by default', () => {
      const decision = engine.evaluateScanner('existing', true);
      expect(decision.action).toBe('warn');
    });

    it('should allow all when disabled', () => {
      engine.updateConfig({ scanner: { enabled: false } as any });
      const decision = engine.evaluateScanner('write', true);
      expect(decision.action).toBe('allow');
    });
  });

  describe('Channel Evaluation', () => {
    it('should allow when no channel policy exists', () => {
      const decision = engine.evaluateChannel('telegram', 'user123');
      expect(decision.action).toBe('allow');
    });

    it('should block blocked contacts', () => {
      engine.updateConfig({
        channels: {
          whatsapp: {
            blockedContacts: ['bad-user'],
            allowUnknown: true,
            quarantineUnknown: false
          }
        }
      });

      const decision = engine.evaluateChannel('whatsapp', 'bad-user');
      expect(decision.action).toBe('block');
    });

    it('should allow listed contacts', () => {
      engine.updateConfig({
        channels: {
          whatsapp: {
            allowedContacts: ['good-user'],
            allowUnknown: false,
            quarantineUnknown: false
          }
        }
      });

      const decision = engine.evaluateChannel('whatsapp', 'good-user');
      expect(decision.action).toBe('allow');
    });

    it('should block unknown contacts when allowUnknown is false', () => {
      engine.updateConfig({
        channels: {
          whatsapp: {
            allowedContacts: ['good-user'],
            allowUnknown: false,
            quarantineUnknown: false
          }
        }
      });

      const decision = engine.evaluateChannel('whatsapp', 'unknown-user');
      expect(decision.action).toBe('block');
    });

    it('should quarantine unknown contacts when configured', () => {
      engine.updateConfig({
        channels: {
          whatsapp: {
            allowedContacts: ['good-user'],
            allowUnknown: true,
            quarantineUnknown: true
          }
        }
      });

      const decision = engine.evaluateChannel('whatsapp', 'unknown-user');
      expect(decision.action).toBe('quarantine');
    });
  });

  describe('Tool Evaluation', () => {
    it('should allow when no tool policy exists', () => {
      const decision = engine.evaluateTool('browser', 'navigate', 'https://example.com');
      expect(decision.action).toBe('allow');
    });

    it('should block disabled tools', () => {
      engine.updateConfig({
        tools: {
          exec: { enabled: false, requiresApproval: false }
        }
      });

      const decision = engine.evaluateTool('exec', 'run', 'ls -la');
      expect(decision.action).toBe('block');
    });

    it('should block on blocked patterns', () => {
      engine.updateConfig({
        tools: {
          exec: {
            enabled: true,
            requiresApproval: false,
            blockedPatterns: ['rm -rf', 'sudo']
          }
        }
      });

      const decision = engine.evaluateTool('exec', 'run', 'sudo rm -rf /');
      expect(decision.action).toBe('block');
    });

    it('should require approval when configured', () => {
      engine.updateConfig({
        tools: {
          message: {
            enabled: true,
            requiresApproval: true
          }
        }
      });

      const decision = engine.evaluateTool('message', 'send', 'hello');
      expect(decision.action).toBe('require_approval');
    });

    it('should block when target does not match allowed patterns', () => {
      engine.updateConfig({
        tools: {
          browser: {
            enabled: true,
            requiresApproval: false,
            allowedPatterns: ['https://github.com.*', 'https://docs..*']
          }
        }
      });

      const decision = engine.evaluateTool('browser', 'navigate', 'https://evil.com');
      expect(decision.action).toBe('block');
    });

    it('should allow when target matches allowed patterns', () => {
      engine.updateConfig({
        tools: {
          browser: {
            enabled: true,
            requiresApproval: false,
            allowedPatterns: ['https://github.com.*']
          }
        }
      });

      const decision = engine.evaluateTool('browser', 'navigate', 'https://github.com/user/repo');
      expect(decision.action).toBe('allow');
    });
  });

  describe('Configuration Updates', () => {
    it('should update shield policy', () => {
      engine.updateConfig({
        shield: { sensitivity: 'high' } as any
      });

      const shield = engine.getShieldPolicy();
      expect(shield?.sensitivity).toBe('high');
    });

    it('should merge nested config', () => {
      engine.updateConfig({
        shield: {
          sensitivity: 'high',
          actions: { onMedium: 'block', onLow: 'allow', onHigh: 'block', onCritical: 'block' }
        } as any
      });

      const shield = engine.getShieldPolicy();
      expect(shield?.sensitivity).toBe('high');
      expect(shield?.actions.onMedium).toBe('block');
      // Enabled should still be true from default
      expect(shield?.enabled).toBe(true);
    });

    it('should update channel policies', () => {
      engine.updateConfig({
        channels: {
          slack: { allowUnknown: false, quarantineUnknown: false }
        }
      });

      const slack = engine.getChannelPolicy('slack');
      expect(slack?.allowUnknown).toBe(false);
    });
  });

  describe('Validation', () => {
    it('should validate correct config', () => {
      const result = engine.validate({
        shield: { sensitivity: 'high' } as any
      });
      expect(result.valid).toBe(true);
    });

    it('should reject invalid sensitivity', () => {
      const result = engine.validate({
        shield: { 
          enabled: true,
          sensitivity: 'invalid' as any,
          actions: { onLow: 'allow', onMedium: 'warn', onHigh: 'block', onCritical: 'block' }
        }
      });
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Shield sensitivity must be low, medium, or high');
    });

    it('should reject invalid scanner actions', () => {
      const result = engine.validate({
        scanner: {
          enabled: true,
          scanOnStartup: true,
          extensions: [],
          excludePaths: [],
          actions: { onRead: 'invalid' as any, onWrite: 'block', onExisting: 'report' }
        }
      });
      expect(result.valid).toBe(false);
    });

    it('should reject too short enclave timeout', () => {
      const result = engine.validate({
        enclave: {
          enabled: true,
          path: '/test',
          protectedFiles: [],
          approval: { channel: 'test', timeoutMs: 100, requireReason: true, showDiff: true },
          summaries: {}
        }
      });
      expect(result.valid).toBe(false);
    });
  });

  describe('File Operations', () => {
    const tempDir = path.join(os.tmpdir(), `clawguard-policy-test-${Date.now()}`);
    const configPath = path.join(tempDir, 'policy.yaml');

    beforeAll(async () => {
      await fs.promises.mkdir(tempDir, { recursive: true });
    });

    afterAll(async () => {
      await fs.promises.rm(tempDir, { recursive: true, force: true });
    });

    it('should save policy to file', async () => {
      await engine.saveToFile(configPath);
      const exists = await fs.promises.stat(configPath).then(() => true).catch(() => false);
      expect(exists).toBe(true);
    });

    it('should load policy from file', async () => {
      // Save a custom config
      engine.updateConfig({ shield: { sensitivity: 'high' } as any });
      await engine.saveToFile(configPath);

      // Create new engine and load
      const newEngine = new PolicyEngine({ configPath });
      await newEngine.loadFromFile();

      const shield = newEngine.getShieldPolicy();
      expect(shield?.sensitivity).toBe('high');
    });

    it('should handle missing file gracefully', async () => {
      const missingPath = path.join(tempDir, 'missing.yaml');
      const newEngine = new PolicyEngine({ configPath: missingPath });
      
      // Should not throw
      await newEngine.loadFromFile();
      
      // Should have defaults
      expect(newEngine.getShieldPolicy()?.enabled).toBe(true);
    });
  });

  describe('Sample Policy Generation', () => {
    it('should generate valid YAML', () => {
      const sample = generateSamplePolicy();
      expect(sample).toContain('shield:');
      expect(sample).toContain('scanner:');
      expect(sample).toContain('enclave:');
      expect(sample).toContain('channels:');
      expect(sample).toContain('tools:');
      expect(sample).toContain('audit:');
    });
  });
});
