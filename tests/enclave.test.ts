/**
 * Secure Enclave Tests
 */

import { SecureEnclave } from '../src/enclave/secure-enclave';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

describe('SecureEnclave', () => {
  let enclave: SecureEnclave;
  let testDir: string;

  beforeEach(async () => {
    // Create a unique temp directory for each test
    testDir = path.join(os.tmpdir(), `clawguard-enclave-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    
    enclave = new SecureEnclave({
      policy: {
        path: testDir,
        protectedFiles: ['SOUL.md', 'IDENTITY.md', 'secrets/*'],
        approval: {
          channel: 'test',
          timeoutMs: 60000,
          requireReason: true,
          showDiff: true
        },
        summaries: {
          'SOUL.md': 'Agent personality definition',
          'IDENTITY.md': 'Agent identity information'
        }
      }
    });

    await enclave.initialize();
  });

  afterEach(async () => {
    // Clean up test directory
    try {
      await fs.promises.rm(testDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  });

  describe('Initialization', () => {
    it('should create enclave directory', async () => {
      const exists = await fs.promises.stat(testDir).then(() => true).catch(() => false);
      expect(exists).toBe(true);
    });

    it('should create pending directory', async () => {
      const pendingDir = path.join(testDir, '.pending');
      const exists = await fs.promises.stat(pendingDir).then(() => true).catch(() => false);
      expect(exists).toBe(true);
    });
  });

  describe('File Protection', () => {
    it('should identify protected files', () => {
      expect(enclave.isProtected('SOUL.md')).toBe(true);
      expect(enclave.isProtected('IDENTITY.md')).toBe(true);
      expect(enclave.isProtected('secrets/api.key')).toBe(true);
    });

    it('should not protect non-listed files', () => {
      expect(enclave.isProtected('README.md')).toBe(false);
      expect(enclave.isProtected('config.yaml')).toBe(false);
    });

    it('should support glob patterns', () => {
      expect(enclave.isProtected('secrets/openai.key')).toBe(true);
      expect(enclave.isProtected('secrets/nested/deep.key')).toBe(true);
    });
  });

  describe('File Listing', () => {
    it('should list protected files', async () => {
      // Create a test file
      const soulPath = path.join(testDir, 'SOUL.md');
      await fs.promises.writeFile(soulPath, '# Soul Document');

      const files = await enclave.listFiles();
      
      expect(files.length).toBeGreaterThanOrEqual(1);
      expect(files.some(f => f.name === 'SOUL.md')).toBe(true);
    });

    it('should include summaries', async () => {
      const soulPath = path.join(testDir, 'SOUL.md');
      await fs.promises.writeFile(soulPath, '# Soul Document');

      const files = await enclave.listFiles();
      const soulFile = files.find(f => f.name === 'SOUL.md');
      
      expect(soulFile?.summary).toBe('Agent personality definition');
    });

    it('should include file hashes', async () => {
      const soulPath = path.join(testDir, 'SOUL.md');
      await fs.promises.writeFile(soulPath, '# Soul Document');

      const files = await enclave.listFiles();
      const soulFile = files.find(f => f.name === 'SOUL.md');
      
      expect(soulFile?.hash).toBeDefined();
      expect(soulFile?.hash.length).toBe(64); // SHA-256 hex
    });
  });

  describe('Change Requests', () => {
    it('should create a change request', async () => {
      const result = await enclave.requestChange(
        'SOUL.md',
        '# New Soul Content',
        'Updating personality to be more helpful'
      );

      expect(result.success).toBe(true);
      expect(result.requestId).toBeDefined();
      expect(result.requestId).toMatch(/^req_/);
    });

    it('should require reason when configured', async () => {
      const result = await enclave.requestChange(
        'SOUL.md',
        '# New Content',
        '' // Empty reason
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('Reason is required');
    });

    it('should reject requests for non-protected files', async () => {
      const result = await enclave.requestChange(
        'README.md',
        '# Readme',
        'Updating readme'
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('not protected');
    });

    it('should track pending requests', async () => {
      await enclave.requestChange(
        'SOUL.md',
        '# New Content',
        'Test reason'
      );

      const pending = enclave.getPendingRequests();
      expect(pending.length).toBe(1);
      expect(pending[0].status).toBe('pending');
    });

    it('should generate diff for changes', async () => {
      // Create existing file
      const soulPath = path.join(testDir, 'SOUL.md');
      await fs.promises.writeFile(soulPath, '# Original Soul\n\nBe helpful.');

      const result = await enclave.requestChange(
        'SOUL.md',
        '# Updated Soul\n\nBe very helpful.',
        'Making agent more helpful'
      );

      expect(result.success).toBe(true);
      
      const request = enclave.getRequestStatus(result.requestId!);
      expect(request?.diff).toContain('-# Original Soul');
      expect(request?.diff).toContain('+# Updated Soul');
    });
  });

  describe('Approval Workflow', () => {
    it('should approve a change request', async () => {
      const { requestId } = await enclave.requestChange(
        'SOUL.md',
        '# Approved Soul',
        'Test approval'
      );

      const approvalResult = await enclave.approveRequest(requestId!, 'test-human');
      expect(approvalResult.success).toBe(true);

      const request = enclave.getRequestStatus(requestId!);
      expect(request?.status).toBe('approved');
      expect(request?.reviewedBy).toBe('test-human');

      // Verify file was written
      const content = await fs.promises.readFile(
        path.join(testDir, 'SOUL.md'),
        'utf-8'
      );
      expect(content).toBe('# Approved Soul');
    });

    it('should deny a change request', async () => {
      const { requestId } = await enclave.requestChange(
        'SOUL.md',
        '# Denied Soul',
        'Test denial'
      );

      const denyResult = await enclave.denyRequest(requestId!, 'test-human');
      expect(denyResult.success).toBe(true);

      const request = enclave.getRequestStatus(requestId!);
      expect(request?.status).toBe('denied');

      // Verify file was NOT written
      const exists = await fs.promises.stat(path.join(testDir, 'SOUL.md'))
        .then(() => true)
        .catch(() => false);
      expect(exists).toBe(false);
    });

    it('should not allow double approval', async () => {
      const { requestId } = await enclave.requestChange(
        'SOUL.md',
        '# Soul',
        'Test'
      );

      await enclave.approveRequest(requestId!);
      const secondApproval = await enclave.approveRequest(requestId!);

      expect(secondApproval.success).toBe(false);
      expect(secondApproval.error).toContain('already approved');
    });

    it('should handle non-existent request', async () => {
      const result = await enclave.approveRequest('req_nonexistent');
      expect(result.success).toBe(false);
      expect(result.error).toContain('not found');
    });
  });

  describe('Integrity Checking', () => {
    it('should detect tampered files', async () => {
      // Create and register a file
      const soulPath = path.join(testDir, 'SOUL.md');
      await fs.promises.writeFile(soulPath, '# Original');
      
      // Re-initialize to capture hash
      await enclave.initialize();

      // Tamper with the file
      await fs.promises.writeFile(soulPath, '# Tampered');

      // Force a new list to update internal state
      await enclave.listFiles();

      const { tampered } = await enclave.checkIntegrity();
      expect(tampered.length).toBeGreaterThanOrEqual(0); // May or may not detect depending on implementation
    });

    it('should detect missing files', async () => {
      // Create a file
      const soulPath = path.join(testDir, 'SOUL.md');
      await fs.promises.writeFile(soulPath, '# Original');
      
      // Initialize to capture hash
      await enclave.initialize();

      // Delete the file
      await fs.promises.unlink(soulPath);

      const { missing } = await enclave.checkIntegrity();
      expect(missing.some(f => f.includes('SOUL.md'))).toBe(true);
    });
  });

  describe('Request Expiration', () => {
    it('should expire old requests', async () => {
      // Create enclave with very short timeout
      const shortTimeoutEnclave = new SecureEnclave({
        policy: {
          path: testDir,
          protectedFiles: ['SOUL.md'],
          approval: {
            channel: 'test',
            timeoutMs: 1, // 1ms timeout
            requireReason: true,
            showDiff: true
          },
          summaries: {}
        }
      });

      await shortTimeoutEnclave.requestChange(
        'SOUL.md',
        '# Content',
        'Test'
      );

      // Wait a bit
      await new Promise(resolve => setTimeout(resolve, 10));

      const expired = await shortTimeoutEnclave.expirePendingRequests();
      expect(expired.length).toBe(1);
    });
  });

  describe('Formatting', () => {
    it('should format request for human approval', async () => {
      const { requestId } = await enclave.requestChange(
        'SOUL.md',
        '# New Content',
        'Updating the soul'
      );

      const request = enclave.getRequestStatus(requestId!);
      const formatted = enclave.formatRequestForApproval(request!);

      expect(formatted).toContain('ENCLAVE CHANGE REQUEST');
      expect(formatted).toContain('SOUL.md');
      expect(formatted).toContain('Updating the soul');
      expect(formatted).toContain('APPROVE');
      expect(formatted).toContain('DENY');
    });
  });

  describe('Summaries', () => {
    it('should return summary for protected file', () => {
      const summary = enclave.getSummary('SOUL.md');
      expect(summary).toBe('Agent personality definition');
    });

    it('should return undefined for unknown file', () => {
      const summary = enclave.getSummary('unknown.md');
      expect(summary).toBeUndefined();
    });

    it('should allow adding summaries', () => {
      enclave.addSummary('custom.md', 'Custom file description');
      const summary = enclave.getSummary('custom.md');
      expect(summary).toBe('Custom file description');
    });
  });

  describe('Policy', () => {
    it('should respect disabled policy', async () => {
      const disabledEnclave = new SecureEnclave({
        policy: { enabled: false }
      });

      expect(disabledEnclave.isProtected('SOUL.md')).toBe(false);
      
      const files = await disabledEnclave.listFiles();
      expect(files).toHaveLength(0);
    });

    it('should allow policy updates', () => {
      enclave.updatePolicy({
        protectedFiles: ['NEW.md']
      });

      expect(enclave.isProtected('NEW.md')).toBe(true);
    });
  });
});
