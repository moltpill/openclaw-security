/**
 * Secure Enclave
 * 
 * A protected directory that only humans can access directly.
 * Agents can request changes, but changes require human approval.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { EnclavePolicy, EnclaveChangeRequest } from '../types';

export interface EnclaveOptions {
  policy?: Partial<EnclavePolicy>;
}

export interface EnclaveFile {
  name: string;
  path: string;
  hash: string;
  lastModified: Date;
  summary?: string;
}

export interface ChangeRequestResult {
  success: boolean;
  requestId?: string;
  error?: string;
}

export class SecureEnclave {
  private policy: EnclavePolicy;
  private pendingRequests: Map<string, EnclaveChangeRequest>;
  private fileHashes: Map<string, string>;

  constructor(options: EnclaveOptions = {}) {
    this.policy = {
      enabled: true,
      path: path.join(process.env.HOME || '~', '.openclaw', 'enclave'),
      protectedFiles: ['SOUL.md', 'IDENTITY.md', 'secrets/*'],
      approval: {
        channel: 'whatsapp',
        timeoutMs: 24 * 60 * 60 * 1000, // 24 hours
        requireReason: true,
        showDiff: true
      },
      summaries: {
        'SOUL.md': 'Defines agent personality, communication style, and boundaries',
        'IDENTITY.md': 'Agent name, avatar, and core identity information'
      },
      ...options.policy
    };

    this.pendingRequests = new Map();
    this.fileHashes = new Map();
  }

  /**
   * Initialize the enclave directory
   */
  async initialize(): Promise<void> {
    if (!this.policy.enabled) return;

    // Create enclave directory if it doesn't exist
    await fs.promises.mkdir(this.policy.path, { recursive: true, mode: 0o700 });
    
    // Create pending directory
    const pendingDir = path.join(this.policy.path, '.pending');
    await fs.promises.mkdir(pendingDir, { recursive: true, mode: 0o700 });

    // Calculate initial hashes for protected files
    await this.updateFileHashes();
  }

  /**
   * List protected files (agent-safe - returns names and summaries only)
   */
  async listFiles(): Promise<EnclaveFile[]> {
    if (!this.policy.enabled) return [];

    const files: EnclaveFile[] = [];

    for (const pattern of this.policy.protectedFiles) {
      const matchedFiles = await this.globFiles(pattern);
      
      for (const filePath of matchedFiles) {
        const name = path.basename(filePath);
        const relativePath = path.relative(this.policy.path, filePath);
        
        try {
          const stats = await fs.promises.stat(filePath);
          const hash = await this.hashFile(filePath);
          
          files.push({
            name,
            path: relativePath,
            hash,
            lastModified: stats.mtime,
            summary: this.policy.summaries[relativePath] || this.policy.summaries[name]
          });
        } catch (error) {
          // File doesn't exist yet
        }
      }
    }

    return files;
  }

  /**
   * Get a summary of a protected file (agent-safe)
   */
  getSummary(fileName: string): string | undefined {
    return this.policy.summaries[fileName];
  }

  /**
   * Check if a path is protected
   */
  isProtected(filePath: string): boolean {
    if (!this.policy.enabled) return false;

    const normalizedPath = filePath.replace(/\\/g, '/');
    
    for (const pattern of this.policy.protectedFiles) {
      if (this.matchesPattern(normalizedPath, pattern)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Request a change to a protected file (agent uses this)
   */
  async requestChange(
    file: string,
    newContent: string,
    reason: string
  ): Promise<ChangeRequestResult> {
    if (!this.policy.enabled) {
      return { success: false, error: 'Enclave is disabled' };
    }

    if (this.policy.approval.requireReason && !reason) {
      return { success: false, error: 'Reason is required for change requests' };
    }

    const fullPath = path.join(this.policy.path, file);

    // Check if file is protected
    if (!this.isProtected(fullPath) && !this.isProtected(file)) {
      return { success: false, error: 'File is not protected by enclave' };
    }

    // Generate request ID
    const requestId = this.generateRequestId();

    // Get current content for diff
    let currentContent = '';
    try {
      currentContent = await fs.promises.readFile(fullPath, 'utf-8');
    } catch {
      // File doesn't exist yet, that's okay
    }

    // Generate diff
    const diff = this.generateDiff(file, currentContent, newContent);

    // Create change request
    const request: EnclaveChangeRequest = {
      id: requestId,
      file,
      diff,
      reason,
      requestedAt: new Date(),
      requestedBy: 'agent',
      status: 'pending'
    };

    // Save pending request
    this.pendingRequests.set(requestId, request);
    
    // Save to disk
    await this.savePendingRequest(request, newContent);

    return { success: true, requestId };
  }

  /**
   * Get status of a change request
   */
  getRequestStatus(requestId: string): EnclaveChangeRequest | undefined {
    return this.pendingRequests.get(requestId);
  }

  /**
   * Approve a change request (human-only)
   */
  async approveRequest(
    requestId: string,
    reviewedBy: string = 'human'
  ): Promise<{ success: boolean; error?: string }> {
    const request = this.pendingRequests.get(requestId);
    
    if (!request) {
      return { success: false, error: 'Request not found' };
    }

    if (request.status !== 'pending') {
      return { success: false, error: `Request is already ${request.status}` };
    }

    // Load the new content
    const pendingContentPath = path.join(
      this.policy.path,
      '.pending',
      `${requestId}.content`
    );

    try {
      const newContent = await fs.promises.readFile(pendingContentPath, 'utf-8');
      const targetPath = path.join(this.policy.path, request.file);

      // Ensure directory exists
      await fs.promises.mkdir(path.dirname(targetPath), { recursive: true });

      // Apply the change
      await fs.promises.writeFile(targetPath, newContent, { mode: 0o600 });

      // Update request status
      request.status = 'approved';
      request.reviewedAt = new Date();
      request.reviewedBy = reviewedBy;

      // Clean up pending files
      await this.cleanupPendingRequest(requestId);

      // Update hash
      await this.updateFileHashes();

      return { success: true };
    } catch (error) {
      return { 
        success: false, 
        error: error instanceof Error ? error.message : 'Unknown error' 
      };
    }
  }

  /**
   * Deny a change request (human-only)
   */
  async denyRequest(
    requestId: string,
    reviewedBy: string = 'human'
  ): Promise<{ success: boolean; error?: string }> {
    const request = this.pendingRequests.get(requestId);
    
    if (!request) {
      return { success: false, error: 'Request not found' };
    }

    if (request.status !== 'pending') {
      return { success: false, error: `Request is already ${request.status}` };
    }

    // Update request status
    request.status = 'denied';
    request.reviewedAt = new Date();
    request.reviewedBy = reviewedBy;

    // Clean up pending files
    await this.cleanupPendingRequest(requestId);

    return { success: true };
  }

  /**
   * Get all pending requests
   */
  getPendingRequests(): EnclaveChangeRequest[] {
    return Array.from(this.pendingRequests.values())
      .filter(r => r.status === 'pending');
  }

  /**
   * Format a change request for display (for sending to human)
   */
  formatRequestForApproval(request: EnclaveChangeRequest): string {
    const lines = [
      '📋 ENCLAVE CHANGE REQUEST',
      '',
      `File: ${request.file}`,
      `Requested by: ${request.requestedBy}`,
      `Time: ${request.requestedAt.toISOString()}`,
      `Reason: ${request.reason}`,
      ''
    ];

    if (this.policy.approval.showDiff) {
      lines.push('--- Changes ---');
      lines.push(request.diff);
      lines.push('');
    }

    lines.push('Reply:');
    lines.push('  ✅ APPROVE - Apply this change');
    lines.push('  ❌ DENY - Reject this change');

    return lines.join('\n');
  }

  /**
   * Check for tampered files (compare hashes)
   */
  async checkIntegrity(): Promise<{ tampered: string[]; missing: string[] }> {
    const tampered: string[] = [];
    const missing: string[] = [];

    for (const [filePath, expectedHash] of this.fileHashes) {
      try {
        const currentHash = await this.hashFile(filePath);
        if (currentHash !== expectedHash) {
          tampered.push(filePath);
        }
      } catch {
        missing.push(filePath);
      }
    }

    return { tampered, missing };
  }

  /**
   * Expire old pending requests
   */
  async expirePendingRequests(): Promise<string[]> {
    const expired: string[] = [];
    const now = Date.now();

    for (const [id, request] of this.pendingRequests) {
      if (request.status === 'pending') {
        const age = now - request.requestedAt.getTime();
        if (age > this.policy.approval.timeoutMs) {
          request.status = 'expired';
          expired.push(id);
          await this.cleanupPendingRequest(id);
        }
      }
    }

    return expired;
  }

  // ============ Private Methods ============

  private async updateFileHashes(): Promise<void> {
    this.fileHashes.clear();

    for (const pattern of this.policy.protectedFiles) {
      const matchedFiles = await this.globFiles(pattern);
      
      for (const filePath of matchedFiles) {
        try {
          const hash = await this.hashFile(filePath);
          this.fileHashes.set(filePath, hash);
        } catch {
          // File doesn't exist yet
        }
      }
    }
  }

  private async hashFile(filePath: string): Promise<string> {
    const content = await fs.promises.readFile(filePath);
    return crypto.createHash('sha256').update(content).digest('hex');
  }

  private generateRequestId(): string {
    const timestamp = Date.now().toString(36);
    const random = crypto.randomBytes(4).toString('hex');
    return `req_${timestamp}_${random}`;
  }

  private generateDiff(file: string, oldContent: string, newContent: string): string {
    const oldLines = oldContent.split('\n');
    const newLines = newContent.split('\n');
    
    const lines: string[] = [
      `--- ${file} (current)`,
      `+++ ${file} (proposed)`,
      ''
    ];

    // Simple line-by-line diff
    const maxLines = Math.max(oldLines.length, newLines.length);
    let contextStart = -1;
    let changes: string[] = [];

    for (let i = 0; i < maxLines; i++) {
      const oldLine = oldLines[i] ?? '';
      const newLine = newLines[i] ?? '';

      if (oldLine !== newLine) {
        if (contextStart === -1) {
          contextStart = Math.max(0, i - 2);
          // Add context before
          for (let j = contextStart; j < i; j++) {
            if (oldLines[j] !== undefined) {
              changes.push(` ${oldLines[j]}`);
            }
          }
        }

        if (oldLines[i] !== undefined) {
          changes.push(`-${oldLine}`);
        }
        if (newLines[i] !== undefined) {
          changes.push(`+${newLine}`);
        }
      } else if (contextStart !== -1 && i < contextStart + 10) {
        changes.push(` ${oldLine}`);
      }
    }

    if (changes.length > 0) {
      lines.push(`@@ -${contextStart + 1} @@`);
      lines.push(...changes);
    } else {
      lines.push('(No changes detected)');
    }

    return lines.join('\n');
  }

  private async savePendingRequest(
    request: EnclaveChangeRequest,
    newContent: string
  ): Promise<void> {
    const pendingDir = path.join(this.policy.path, '.pending');
    
    // Save request metadata
    const metaPath = path.join(pendingDir, `${request.id}.json`);
    await fs.promises.writeFile(
      metaPath,
      JSON.stringify(request, null, 2),
      { mode: 0o600 }
    );

    // Save new content
    const contentPath = path.join(pendingDir, `${request.id}.content`);
    await fs.promises.writeFile(contentPath, newContent, { mode: 0o600 });

    // Save diff
    const diffPath = path.join(pendingDir, `${request.id}.diff`);
    await fs.promises.writeFile(diffPath, request.diff, { mode: 0o600 });
  }

  private async cleanupPendingRequest(requestId: string): Promise<void> {
    const pendingDir = path.join(this.policy.path, '.pending');
    
    const files = [
      `${requestId}.json`,
      `${requestId}.content`,
      `${requestId}.diff`
    ];

    for (const file of files) {
      try {
        await fs.promises.unlink(path.join(pendingDir, file));
      } catch {
        // File might not exist
      }
    }
  }

  private async globFiles(pattern: string): Promise<string[]> {
    const files: string[] = [];
    const basePath = this.policy.path;

    if (pattern.includes('*')) {
      // Simple glob support
      const dir = path.dirname(pattern);
      const filePattern = path.basename(pattern);
      const fullDir = path.join(basePath, dir === '.' ? '' : dir);

      try {
        const entries = await fs.promises.readdir(fullDir);
        for (const entry of entries) {
          if (this.matchesGlob(entry, filePattern)) {
            files.push(path.join(fullDir, entry));
          }
        }
      } catch {
        // Directory doesn't exist
      }
    } else {
      // Exact file
      files.push(path.join(basePath, pattern));
    }

    return files;
  }

  private matchesGlob(fileName: string, pattern: string): boolean {
    if (pattern === '*') return true;
    if (pattern.startsWith('*.')) {
      return fileName.endsWith(pattern.slice(1));
    }
    return fileName === pattern;
  }

  private matchesPattern(filePath: string, pattern: string): boolean {
    const normalizedPattern = pattern.replace(/\\/g, '/');
    
    if (normalizedPattern.includes('*')) {
      // Convert glob to regex
      const regex = new RegExp(
        '^' + normalizedPattern.replace(/\*/g, '.*') + '$'
      );
      return regex.test(filePath);
    }
    
    return filePath.endsWith(normalizedPattern) || 
           filePath.includes(`/${normalizedPattern}`);
  }

  /**
   * Update policy
   */
  updatePolicy(policy: Partial<EnclavePolicy>): void {
    this.policy = { ...this.policy, ...policy };
    if (policy.summaries) {
      this.policy.summaries = { ...this.policy.summaries, ...policy.summaries };
    }
  }

  /**
   * Add a summary for a protected file
   */
  addSummary(fileName: string, summary: string): void {
    this.policy.summaries[fileName] = summary;
  }
}
