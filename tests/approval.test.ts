/**
 * Approval Channel Tests
 */

import { ApprovalChannel, ApprovalManager } from '../src/approval';
import { SecureEnclave } from '../src/enclave/secure-enclave';
import { EnclaveChangeRequest } from '../src/types';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

describe('ApprovalChannel', () => {
  let channel: ApprovalChannel;
  let testDir: string;

  beforeEach(async () => {
    testDir = path.join(os.tmpdir(), `clawguard-approval-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    await fs.promises.mkdir(testDir, { recursive: true });

    channel = new ApprovalChannel({
      channel: 'whatsapp',
      target: '+1234567890',
      defaultTimeoutMs: 60000,
      persistPath: path.join(testDir, 'pending.json'),
      maxDiffLines: 10
    });

    await channel.initialize();
  });

  afterEach(async () => {
    try {
      await fs.promises.rm(testDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  });

  describe('Message Creation', () => {
    it('should create approval message from change request', () => {
      const request: EnclaveChangeRequest = {
        id: 'req_test123',
        file: 'SOUL.md',
        diff: '--- SOUL.md (current)\n+++ SOUL.md (proposed)\n@@ -1 @@\n-Old content\n+New content',
        reason: 'Updating personality',
        requestedAt: new Date(),
        requestedBy: 'agent',
        status: 'pending'
      };

      const { message, pending, command } = channel.createApprovalMessage(request);

      expect(message).toContain('APPROVAL NEEDED');
      expect(message).toContain('SOUL.md');
      expect(message).toContain('Updating personality');
      expect(message).toContain('req_test123');
      expect(message).toContain('YES');
      expect(message).toContain('NO');

      expect(pending.requestId).toBe('req_test123');
      expect(pending.file).toBe('SOUL.md');
      expect(pending.channel).toBe('whatsapp');
      expect(pending.target).toBe('+1234567890');

      expect(command.action).toBe('send');
      expect(command.channel).toBe('whatsapp');
      expect(command.target).toBe('+1234567890');
    });

    it('should include diff in message', () => {
      const request: EnclaveChangeRequest = {
        id: 'req_test',
        file: 'SOUL.md',
        diff: '-Line 1\n+Line 2\n+Line 3',
        reason: 'Test',
        requestedAt: new Date(),
        requestedBy: 'agent',
        status: 'pending'
      };

      const { message } = channel.createApprovalMessage(request);

      expect(message).toContain('-Line 1');
      expect(message).toContain('+Line 2');
    });

    it('should truncate long diffs', () => {
      const longDiff = Array(20).fill('+Long line content').join('\n');
      const request: EnclaveChangeRequest = {
        id: 'req_test',
        file: 'SOUL.md',
        diff: longDiff,
        reason: 'Test',
        requestedAt: new Date(),
        requestedBy: 'agent',
        status: 'pending'
      };

      const { message } = channel.createApprovalMessage(request);

      expect(message).toContain('more lines');
    });

    it('should format expiry time correctly', () => {
      const request: EnclaveChangeRequest = {
        id: 'req_test',
        file: 'SOUL.md',
        diff: '',
        reason: 'Test',
        requestedAt: new Date(),
        requestedBy: 'agent',
        status: 'pending'
      };

      // 90 minute timeout
      const { message } = channel.createApprovalMessage(request, 90 * 60 * 1000);
      expect(message).toMatch(/1h 30m|1h 29m/); // Allow for small timing variation
    });
  });

  describe('Pending Management', () => {
    it('should register and retrieve pending approvals', async () => {
      const pending = {
        requestId: 'req_abc123',
        file: 'SOUL.md',
        reason: 'Test',
        diff: '',
        requestedBy: 'agent',
        requestedAt: new Date(),
        expiresAt: new Date(Date.now() + 60000),
        channel: 'whatsapp',
        target: '+1234567890'
      };

      await channel.registerPending(pending, 'msg_123');

      const retrieved = channel.getPending('req_abc123');
      expect(retrieved).toBeDefined();
      expect(retrieved?.messageId).toBe('msg_123');
    });

    it('should list all pending approvals', async () => {
      const pending1 = {
        requestId: 'req_1',
        file: 'FILE1.md',
        reason: 'Test 1',
        diff: '',
        requestedBy: 'agent',
        requestedAt: new Date(),
        expiresAt: new Date(Date.now() + 60000),
        channel: 'whatsapp',
        target: '+1234567890'
      };

      const pending2 = {
        requestId: 'req_2',
        file: 'FILE2.md',
        reason: 'Test 2',
        diff: '',
        requestedBy: 'agent',
        requestedAt: new Date(),
        expiresAt: new Date(Date.now() + 60000),
        channel: 'whatsapp',
        target: '+1234567890'
      };

      await channel.registerPending(pending1);
      await channel.registerPending(pending2);

      const all = channel.getAllPending();
      expect(all.length).toBe(2);
    });

    it('should persist pending approvals to disk', async () => {
      const pending = {
        requestId: 'req_persist',
        file: 'SOUL.md',
        reason: 'Test',
        diff: '',
        requestedBy: 'agent',
        requestedAt: new Date(),
        expiresAt: new Date(Date.now() + 60000),
        channel: 'whatsapp',
        target: '+1234567890'
      };

      await channel.registerPending(pending);

      // Create new channel instance and load
      const newChannel = new ApprovalChannel({
        channel: 'whatsapp',
        target: '+1234567890',
        persistPath: path.join(testDir, 'pending.json')
      });
      await newChannel.initialize();

      const loaded = newChannel.getPending('req_persist');
      expect(loaded).toBeDefined();
      expect(loaded?.file).toBe('SOUL.md');
    });
  });

  describe('Response Parsing', () => {
    beforeEach(async () => {
      // Register a pending approval
      await channel.registerPending({
        requestId: 'req_parse',
        file: 'SOUL.md',
        reason: 'Test',
        diff: '',
        requestedBy: 'agent',
        requestedAt: new Date(),
        expiresAt: new Date(Date.now() + 60000),
        channel: 'whatsapp',
        target: '+1234567890'
      });
    });

    it('should parse YES as approval', () => {
      const response = channel.parseResponse('YES');
      expect(response).not.toBeNull();
      expect(response?.approved).toBe(true);
    });

    it('should parse APPROVE as approval', () => {
      const response = channel.parseResponse('approve');
      expect(response).not.toBeNull();
      expect(response?.approved).toBe(true);
    });

    it('should parse NO as denial', () => {
      const response = channel.parseResponse('NO');
      expect(response).not.toBeNull();
      expect(response?.approved).toBe(false);
    });

    it('should parse DENY as denial', () => {
      const response = channel.parseResponse('deny');
      expect(response).not.toBeNull();
      expect(response?.approved).toBe(false);
    });

    it('should parse ✅ emoji as approval', () => {
      const response = channel.parseResponse('✅');
      expect(response).not.toBeNull();
      expect(response?.approved).toBe(true);
    });

    it('should parse ❌ emoji as denial', () => {
      const response = channel.parseResponse('❌');
      expect(response).not.toBeNull();
      expect(response?.approved).toBe(false);
    });

    it('should extract request ID from message', async () => {
      await channel.registerPending({
        requestId: 'req_specific123',
        file: 'OTHER.md',
        reason: 'Test',
        diff: '',
        requestedBy: 'agent',
        requestedAt: new Date(Date.now() - 1000), // Older
        expiresAt: new Date(Date.now() + 60000),
        channel: 'whatsapp',
        target: '+1234567890'
      });

      const response = channel.parseResponse('YES req_specific123');
      expect(response?.requestId).toBe('req_specific123');
    });

    it('should use most recent pending if no ID specified', () => {
      const response = channel.parseResponse('YES');
      expect(response?.requestId).toBe('req_parse');
    });

    it('should return null for unrelated messages', () => {
      const response = channel.parseResponse('Hello, how are you?');
      expect(response).toBeNull();
    });

    it('should include sender ID', () => {
      const response = channel.parseResponse('YES', 'user@example.com');
      expect(response?.respondedBy).toBe('user@example.com');
    });
  });

  describe('Expiry Handling', () => {
    it('should detect expired approvals', async () => {
      await channel.registerPending({
        requestId: 'req_expired',
        file: 'SOUL.md',
        reason: 'Test',
        diff: '',
        requestedBy: 'agent',
        requestedAt: new Date(Date.now() - 120000), // 2 minutes ago
        expiresAt: new Date(Date.now() - 60000), // Expired 1 minute ago
        channel: 'whatsapp',
        target: '+1234567890'
      });

      const expired = await channel.checkExpired();
      expect(expired.length).toBe(1);
      expect(expired[0].requestId).toBe('req_expired');
    });

    it('should remove expired from pending list', async () => {
      await channel.registerPending({
        requestId: 'req_expired',
        file: 'SOUL.md',
        reason: 'Test',
        diff: '',
        requestedBy: 'agent',
        requestedAt: new Date(),
        expiresAt: new Date(Date.now() - 1000), // Already expired
        channel: 'whatsapp',
        target: '+1234567890'
      });

      await channel.checkExpired();

      expect(channel.getPending('req_expired')).toBeUndefined();
    });

    it('should not match expired requests', async () => {
      await channel.registerPending({
        requestId: 'req_expired',
        file: 'SOUL.md',
        reason: 'Test',
        diff: '',
        requestedBy: 'agent',
        requestedAt: new Date(),
        expiresAt: new Date(Date.now() - 1000), // Expired
        channel: 'whatsapp',
        target: '+1234567890'
      });

      const response = channel.parseResponse('YES req_expired');
      const matched = channel.matchResponse(response!);

      expect(matched).toBeNull();
    });
  });

  describe('Confirmation Messages', () => {
    const pending = {
      requestId: 'req_test',
      file: 'SOUL.md',
      reason: 'Test',
      diff: '',
      requestedBy: 'agent',
      requestedAt: new Date(),
      expiresAt: new Date(Date.now() + 60000),
      channel: 'whatsapp',
      target: '+1234567890'
    };

    it('should create approved message', () => {
      const command = channel.createApprovedMessage(pending);
      expect(command.message).toContain('approved');
      expect(command.message).toContain('SOUL.md');
    });

    it('should create denied message', () => {
      const command = channel.createDeniedMessage(pending);
      expect(command.message).toContain('denied');
      expect(command.message).toContain('SOUL.md');
    });

    it('should create expired message', () => {
      const command = channel.createExpiredMessage(pending);
      expect(command.message).toContain('expired');
      expect(command.message).toContain('SOUL.md');
    });
  });
});


describe('ApprovalManager', () => {
  let manager: ApprovalManager;
  let enclave: SecureEnclave;
  let testDir: string;
  let sentMessages: any[];

  beforeEach(async () => {
    testDir = path.join(os.tmpdir(), `clawguard-manager-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    
    enclave = new SecureEnclave({
      policy: {
        path: testDir,
        protectedFiles: ['SOUL.md', 'IDENTITY.md'],
        approval: {
          channel: 'whatsapp',
          timeoutMs: 60000,
          requireReason: true,
          showDiff: true
        },
        summaries: {
          'SOUL.md': 'Agent personality'
        }
      }
    });

    await enclave.initialize();

    sentMessages = [];

    manager = new ApprovalManager({
      enclave,
      channel: {
        channel: 'whatsapp',
        target: '+1234567890',
        defaultTimeoutMs: 60000,
        persistPath: path.join(testDir, '.pending', 'approval-state.json')
      },
      onSendMessage: async (command) => {
        sentMessages.push(command);
        return `msg_${Date.now()}`;
      },
      expiryCheckIntervalMs: 1000000 // Disable auto-check for tests
    });

    await manager.initialize();
  });

  afterEach(async () => {
    manager.stop();
    try {
      await fs.promises.rm(testDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  });

  describe('Full Workflow', () => {
    it('should complete approval workflow', async () => {
      // 1. Request approval
      const result = await manager.requestApproval(
        'SOUL.md',
        '# New Soul Content',
        'Updating personality'
      );

      expect(result.success).toBe(true);
      expect(result.requestId).toBeDefined();
      expect(sentMessages.length).toBe(1);
      expect(sentMessages[0].message).toContain('SOUL.md');

      // 2. Check pending
      const pending = manager.getAllPendingApprovals();
      expect(pending.length).toBe(1);

      // 3. Process approval response
      const processResult = await manager.processIncomingMessage('YES');

      expect(processResult.matched).toBe(true);
      expect(processResult.action).toBe('approved');
      expect(sentMessages.length).toBe(2); // Confirmation sent

      // 4. Verify file was written
      const content = await fs.promises.readFile(
        path.join(testDir, 'SOUL.md'),
        'utf-8'
      );
      expect(content).toBe('# New Soul Content');

      // 5. Check no more pending
      expect(manager.getAllPendingApprovals().length).toBe(0);
    });

    it('should complete denial workflow', async () => {
      // 1. Request approval
      const result = await manager.requestApproval(
        'SOUL.md',
        '# New Soul Content',
        'Updating personality'
      );

      expect(result.success).toBe(true);

      // 2. Process denial response
      const processResult = await manager.processIncomingMessage('NO');

      expect(processResult.matched).toBe(true);
      expect(processResult.action).toBe('denied');

      // 3. Verify file was NOT written
      const exists = await fs.promises.stat(path.join(testDir, 'SOUL.md'))
        .then(() => true)
        .catch(() => false);
      expect(exists).toBe(false);
    });

    it('should handle multiple pending requests', async () => {
      // Create two requests
      const result1 = await manager.requestApproval(
        'SOUL.md',
        '# Soul 1',
        'First update'
      );

      const result2 = await manager.requestApproval(
        'IDENTITY.md',
        '# Identity 1',
        'Second update'
      );

      expect(result1.success).toBe(true);
      expect(result2.success).toBe(true);

      // Approve specific request
      await manager.processIncomingMessage(`YES ${result2.requestId}`);

      // Check IDENTITY.md was created, SOUL.md wasn't
      const identityExists = await fs.promises.stat(path.join(testDir, 'IDENTITY.md'))
        .then(() => true)
        .catch(() => false);
      const soulExists = await fs.promises.stat(path.join(testDir, 'SOUL.md'))
        .then(() => true)
        .catch(() => false);

      expect(identityExists).toBe(true);
      expect(soulExists).toBe(false);

      // One pending remains
      expect(manager.getAllPendingApprovals().length).toBe(1);
    });
  });

  describe('Error Handling', () => {
    it('should reject non-protected files', async () => {
      const result = await manager.requestApproval(
        'README.md',
        '# Readme',
        'Update readme'
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('not protected');
    });

    it('should reject without reason', async () => {
      const result = await manager.requestApproval(
        'SOUL.md',
        '# Content',
        '' // No reason
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('Reason is required');
    });

    it('should handle unknown response request', async () => {
      const result = await manager.processIncomingMessage('YES req_unknown');

      expect(result.matched).toBe(true);
      expect(result.action).toBe('not_found');
    });

    it('should handle non-matching messages', async () => {
      const result = await manager.processIncomingMessage('Hello there!');

      expect(result.matched).toBe(false);
    });
  });

  describe('Status Checking', () => {
    it('should get request status', async () => {
      const { requestId } = await manager.requestApproval(
        'SOUL.md',
        '# Content',
        'Test'
      );

      const status = manager.getRequestStatus(requestId!);

      expect(status.enclave).toBeDefined();
      expect(status.enclave?.status).toBe('pending');
      expect(status.pending).toBeDefined();
      expect(status.pending?.file).toBe('SOUL.md');
    });
  });

  describe('Expiry', () => {
    it('should handle expiry checking', async () => {
      // Create a request with very short timeout
      const shortTimeoutManager = new ApprovalManager({
        enclave,
        channel: {
          channel: 'whatsapp',
          target: '+1234567890',
          defaultTimeoutMs: 1, // 1ms timeout
          persistPath: path.join(testDir, '.pending', 'short-timeout.json')
        },
        onSendMessage: async (command) => {
          sentMessages.push(command);
        },
        expiryCheckIntervalMs: 1000000
      });

      await shortTimeoutManager.initialize();

      await shortTimeoutManager.requestApproval(
        'SOUL.md',
        '# Content',
        'Test'
      );

      // Wait for expiry
      await new Promise(resolve => setTimeout(resolve, 10));

      const expired = await shortTimeoutManager.checkExpiredRequests();

      expect(expired.length).toBe(1);
      expect(shortTimeoutManager.getAllPendingApprovals().length).toBe(0);

      shortTimeoutManager.stop();
    });

    it('should manually expire request', async () => {
      const { requestId } = await manager.requestApproval(
        'SOUL.md',
        '# Content',
        'Test'
      );

      const result = await manager.expireRequest(requestId!);

      expect(result).toBe(true);
      expect(manager.getAllPendingApprovals().length).toBe(0);
    });
  });

  describe('Resend', () => {
    it('should resend approval request', async () => {
      const { requestId } = await manager.requestApproval(
        'SOUL.md',
        '# Content',
        'Test'
      );

      const initialCount = sentMessages.length;

      const command = await manager.resendApprovalRequest(requestId!);

      expect(command).not.toBeNull();
      expect(sentMessages.length).toBe(initialCount + 1);
    });

    it('should not resend resolved request', async () => {
      const { requestId } = await manager.requestApproval(
        'SOUL.md',
        '# Content',
        'Test'
      );

      // Approve it
      await manager.processIncomingMessage('YES');

      // Try to resend
      const command = await manager.resendApprovalRequest(requestId!);

      expect(command).toBeNull();
    });
  });
});
