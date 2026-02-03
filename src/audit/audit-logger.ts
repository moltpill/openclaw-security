/**
 * Audit Logger
 * 
 * Logs security-related events for compliance, debugging,
 * and incident review.
 */

import * as fs from 'fs';
import * as path from 'path';
import { AuditEvent, AuditEventType, AuditPolicy, Threat } from '../types';

export interface AuditLoggerOptions {
  policy?: Partial<AuditPolicy>;
}

export interface LogEntry {
  timestamp: string;
  level: 'info' | 'warn' | 'error' | 'critical';
  eventType: AuditEventType;
  message: string;
  data?: Record<string, unknown>;
  sessionId?: string;
  correlationId?: string;
}

export class AuditLogger {
  private policy: AuditPolicy;
  private buffer: LogEntry[] = [];
  private flushInterval?: NodeJS.Timeout;
  private logFilePath?: string;

  constructor(options: AuditLoggerOptions = {}) {
    this.policy = {
      enabled: true,
      logPath: path.join(process.env.HOME || '~', '.openclaw', 'logs', 'clawguard'),
      retentionDays: 30,
      logLevel: 'standard',
      includeContent: false,
      ...options.policy
    };

    if (this.policy.enabled) {
      this.initializeLogFile();
      this.startFlushInterval();
    }
  }

  /**
   * Log an audit event
   */
  log(event: AuditEvent): void {
    if (!this.policy.enabled) return;

    const entry = this.formatEvent(event);
    
    // Apply log level filter
    if (!this.shouldLog(entry)) return;

    this.buffer.push(entry);

    // Immediate flush for critical events
    if (entry.level === 'critical') {
      this.flush();
    }
  }

  /**
   * Log a message received
   */
  logMessageInbound(data: {
    channel: string;
    senderId?: string;
    contentHash?: string;
    threatIndicators?: Threat[];
    sessionId?: string;
  }): void {
    this.log({
      timestamp: new Date(),
      eventType: AuditEventType.MESSAGE_INBOUND,
      sessionId: data.sessionId,
      data: {
        channel: data.channel,
        senderId: data.senderId,
        contentHash: data.contentHash
      },
      threatIndicators: data.threatIndicators
    });
  }

  /**
   * Log a message sent
   */
  logMessageOutbound(data: {
    channel: string;
    targetId?: string;
    contentHash?: string;
    sessionId?: string;
  }): void {
    this.log({
      timestamp: new Date(),
      eventType: AuditEventType.MESSAGE_OUTBOUND,
      sessionId: data.sessionId,
      data: {
        channel: data.channel,
        targetId: data.targetId,
        contentHash: data.contentHash
      }
    });
  }

  /**
   * Log a tool invocation
   */
  logToolInvocation(data: {
    tool: string;
    operation?: string;
    target?: string;
    allowed: boolean;
    reason?: string;
    sessionId?: string;
  }): void {
    this.log({
      timestamp: new Date(),
      eventType: AuditEventType.TOOL_INVOCATION,
      sessionId: data.sessionId,
      data: {
        tool: data.tool,
        operation: data.operation,
        target: data.target,
        allowed: data.allowed,
        reason: data.reason
      }
    });
  }

  /**
   * Log a threat detection
   */
  logThreatDetected(data: {
    source: string;
    threats: Threat[];
    action: string;
    sessionId?: string;
    correlationId?: string;
  }): void {
    this.log({
      timestamp: new Date(),
      eventType: AuditEventType.THREAT_DETECTED,
      sessionId: data.sessionId,
      correlationId: data.correlationId,
      data: {
        source: data.source,
        threatCount: data.threats.length,
        maxSeverity: Math.max(...data.threats.map(t => t.severity)),
        action: data.action
      },
      threatIndicators: data.threats
    });
  }

  /**
   * Log a policy decision
   */
  logPolicyDecision(data: {
    policyType: string;
    input: Record<string, unknown>;
    decision: string;
    reason: string;
    sessionId?: string;
  }): void {
    this.log({
      timestamp: new Date(),
      eventType: AuditEventType.POLICY_DECISION,
      sessionId: data.sessionId,
      data: {
        policyType: data.policyType,
        input: data.input,
        decision: data.decision,
        reason: data.reason
      }
    });
  }

  /**
   * Log an enclave change request
   */
  logEnclaveRequest(data: {
    requestId: string;
    file: string;
    reason: string;
    sessionId?: string;
  }): void {
    this.log({
      timestamp: new Date(),
      eventType: AuditEventType.ENCLAVE_REQUEST,
      sessionId: data.sessionId,
      data: {
        requestId: data.requestId,
        file: data.file,
        reason: data.reason
      }
    });
  }

  /**
   * Log an enclave decision
   */
  logEnclaveDecision(data: {
    requestId: string;
    decision: 'approved' | 'denied' | 'expired';
    reviewedBy?: string;
    sessionId?: string;
  }): void {
    this.log({
      timestamp: new Date(),
      eventType: AuditEventType.ENCLAVE_DECISION,
      sessionId: data.sessionId,
      data: {
        requestId: data.requestId,
        decision: data.decision,
        reviewedBy: data.reviewedBy
      }
    });
  }

  /**
   * Log a secret detection
   */
  logSecretDetected(data: {
    filePath: string;
    secretType: string;
    action: string;
    redacted: boolean;
    sessionId?: string;
  }): void {
    this.log({
      timestamp: new Date(),
      eventType: AuditEventType.SECRET_DETECTED,
      sessionId: data.sessionId,
      data: {
        filePath: data.filePath,
        secretType: data.secretType,
        action: data.action,
        redacted: data.redacted
      }
    });
  }

  /**
   * Log a config change
   */
  logConfigChange(data: {
    section: string;
    changes: Record<string, unknown>;
    sessionId?: string;
  }): void {
    this.log({
      timestamp: new Date(),
      eventType: AuditEventType.CONFIG_CHANGE,
      sessionId: data.sessionId,
      data: {
        section: data.section,
        changes: data.changes
      }
    });
  }

  /**
   * Flush buffered logs to disk
   */
  async flush(): Promise<void> {
    if (this.buffer.length === 0) return;

    const entries = [...this.buffer];
    this.buffer = [];

    if (!this.logFilePath) return;

    const lines = entries.map(e => JSON.stringify(e)).join('\n') + '\n';

    try {
      await fs.promises.appendFile(this.logFilePath, lines);
    } catch (error) {
      // Re-add entries to buffer if write fails
      this.buffer.unshift(...entries);
      console.error('Failed to write audit log:', error);
    }
  }

  /**
   * Get recent log entries
   */
  async getRecentLogs(options: {
    limit?: number;
    eventType?: AuditEventType;
    since?: Date;
    sessionId?: string;
  } = {}): Promise<LogEntry[]> {
    const limit = options.limit || 100;
    const entries: LogEntry[] = [];

    // Include buffer
    entries.push(...this.buffer);

    // Read from file if exists
    if (this.logFilePath) {
      try {
        const content = await fs.promises.readFile(this.logFilePath, 'utf-8');
        const lines = content.trim().split('\n').filter(l => l);
        
        for (const line of lines) {
          try {
            const entry = JSON.parse(line) as LogEntry;
            entries.push(entry);
          } catch {
            // Skip invalid lines
          }
        }
      } catch {
        // File doesn't exist yet
      }
    }

    // Apply filters
    let filtered = entries;

    if (options.eventType) {
      filtered = filtered.filter(e => e.eventType === options.eventType);
    }

    if (options.sessionId) {
      filtered = filtered.filter(e => e.sessionId === options.sessionId);
    }

    if (options.since) {
      filtered = filtered.filter(e => new Date(e.timestamp) >= options.since!);
    }

    // Sort by timestamp descending and limit
    return filtered
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
      .slice(0, limit);
  }

  /**
   * Search logs by text
   */
  async searchLogs(query: string, limit = 50): Promise<LogEntry[]> {
    const all = await this.getRecentLogs({ limit: 1000 });
    const lowerQuery = query.toLowerCase();

    return all
      .filter(entry => {
        const str = JSON.stringify(entry).toLowerCase();
        return str.includes(lowerQuery);
      })
      .slice(0, limit);
  }

  /**
   * Get log statistics
   */
  async getStats(since?: Date): Promise<{
    totalEvents: number;
    byType: Record<string, number>;
    byLevel: Record<string, number>;
    threatCount: number;
  }> {
    const logs = await this.getRecentLogs({ since, limit: 10000 });

    const byType: Record<string, number> = {};
    const byLevel: Record<string, number> = {};
    let threatCount = 0;

    for (const log of logs) {
      byType[log.eventType] = (byType[log.eventType] || 0) + 1;
      byLevel[log.level] = (byLevel[log.level] || 0) + 1;

      if (log.eventType === AuditEventType.THREAT_DETECTED) {
        threatCount++;
      }
    }

    return {
      totalEvents: logs.length,
      byType,
      byLevel,
      threatCount
    };
  }

  /**
   * Clean up old logs
   */
  async cleanup(): Promise<{ deletedFiles: number }> {
    const logDir = this.policy.logPath.replace('~', process.env.HOME || '');
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - this.policy.retentionDays);

    let deletedFiles = 0;

    try {
      const files = await fs.promises.readdir(logDir);

      for (const file of files) {
        if (!file.endsWith('.log')) continue;

        const filePath = path.join(logDir, file);
        const stats = await fs.promises.stat(filePath);

        if (stats.mtime < cutoffDate) {
          await fs.promises.unlink(filePath);
          deletedFiles++;
        }
      }
    } catch {
      // Directory might not exist
    }

    return { deletedFiles };
  }

  /**
   * Stop the logger
   */
  async stop(): Promise<void> {
    if (this.flushInterval) {
      clearInterval(this.flushInterval);
    }
    await this.flush();
  }

  /**
   * Update policy
   */
  updatePolicy(policy: Partial<AuditPolicy>): void {
    this.policy = { ...this.policy, ...policy };
  }

  // ============ Private Methods ============

  private initializeLogFile(): void {
    const logDir = this.policy.logPath.replace('~', process.env.HOME || '');
    const date = new Date().toISOString().split('T')[0];
    this.logFilePath = path.join(logDir, `clawguard-${date}.log`);

    // Ensure directory exists (sync for constructor)
    try {
      fs.mkdirSync(logDir, { recursive: true });
    } catch {
      // Might already exist
    }
  }

  private startFlushInterval(): void {
    // Flush every 5 seconds
    this.flushInterval = setInterval(() => this.flush(), 5000);
  }

  private formatEvent(event: AuditEvent): LogEntry {
    const level = this.getEventLevel(event);
    const message = this.getEventMessage(event);

    const entry: LogEntry = {
      timestamp: event.timestamp.toISOString(),
      level,
      eventType: event.eventType,
      message,
      sessionId: event.sessionId,
      correlationId: event.correlationId
    };

    // Include data based on log level
    if (this.policy.logLevel !== 'minimal') {
      entry.data = this.sanitizeData(event.data);
    }

    // Include threats in verbose mode
    if (this.policy.logLevel === 'verbose' && event.threatIndicators) {
      entry.data = {
        ...entry.data,
        threats: event.threatIndicators
      };
    }

    return entry;
  }

  private getEventLevel(event: AuditEvent): LogEntry['level'] {
    switch (event.eventType) {
      case AuditEventType.THREAT_DETECTED:
        if (event.threatIndicators?.some(t => t.severity >= 3)) {
          return 'critical';
        }
        return 'warn';
      
      case AuditEventType.SECRET_DETECTED:
        return 'warn';
      
      case AuditEventType.ENCLAVE_REQUEST:
      case AuditEventType.ENCLAVE_DECISION:
        return 'warn';
      
      case AuditEventType.POLICY_DECISION:
        return event.data?.decision === 'block' ? 'warn' : 'info';
      
      default:
        return 'info';
    }
  }

  private getEventMessage(event: AuditEvent): string {
    switch (event.eventType) {
      case AuditEventType.MESSAGE_INBOUND:
        return `Inbound message from ${event.data?.channel || 'unknown'}`;
      
      case AuditEventType.MESSAGE_OUTBOUND:
        return `Outbound message to ${event.data?.channel || 'unknown'}`;
      
      case AuditEventType.TOOL_INVOCATION:
        return `Tool ${event.data?.tool || 'unknown'}: ${event.data?.allowed ? 'allowed' : 'blocked'}`;
      
      case AuditEventType.THREAT_DETECTED:
        return `Threat detected: ${event.data?.threatCount || 0} indicator(s)`;
      
      case AuditEventType.POLICY_DECISION:
        return `Policy ${event.data?.policyType}: ${event.data?.decision}`;
      
      case AuditEventType.ENCLAVE_REQUEST:
        return `Enclave change requested: ${event.data?.file}`;
      
      case AuditEventType.ENCLAVE_DECISION:
        return `Enclave request ${event.data?.decision}: ${event.data?.requestId}`;
      
      case AuditEventType.SECRET_DETECTED:
        return `Secret detected: ${event.data?.secretType} in ${event.data?.filePath}`;
      
      case AuditEventType.CONFIG_CHANGE:
        return `Config changed: ${event.data?.section}`;
      
      default:
        return `Event: ${event.eventType}`;
    }
  }

  private sanitizeData(data?: Record<string, unknown>): Record<string, unknown> | undefined {
    if (!data) return undefined;

    // Remove potentially sensitive fields if includeContent is false
    if (!this.policy.includeContent) {
      const sanitized = { ...data };
      delete sanitized.content;
      delete sanitized.body;
      delete sanitized.text;
      delete sanitized.message;
      return sanitized;
    }

    return data;
  }

  private shouldLog(entry: LogEntry): boolean {
    switch (this.policy.logLevel) {
      case 'minimal':
        // Only log warnings and above
        return entry.level === 'warn' || entry.level === 'error' || entry.level === 'critical';
      
      case 'standard':
        // Log everything except verbose info
        return true;
      
      case 'verbose':
        // Log everything
        return true;
      
      default:
        return true;
    }
  }
}
