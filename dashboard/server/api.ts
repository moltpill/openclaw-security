/**
 * ClawGuard Dashboard API Routes
 */

import { Router } from 'express';
import path from 'path';
import { fileURLToPath } from 'url';

// Dynamic import for ClawGuard (parent package)
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const clawguardPath = path.resolve(__dirname, '../../src/index.js');

let clawguard: any = null;
let guardInstance: any = null;

async function getGuard() {
  if (guardInstance) return guardInstance;
  
  try {
    // Try to import the compiled ClawGuard
    clawguard = await import(clawguardPath);
    guardInstance = new clawguard.ClawGuard();
    await guardInstance.initialize();
    return guardInstance;
  } catch (err) {
    console.error('Failed to load ClawGuard:', err);
    // Return mock instance for development
    return createMockGuard();
  }
}

function createMockGuard() {
  return {
    audit: {
      getRecentLogs: async (opts: any = {}) => {
        const limit = opts.limit || 50;
        const now = Date.now();
        return Array.from({ length: Math.min(limit, 20) }, (_, i) => ({
          timestamp: new Date(now - i * 60000 * 5).toISOString(),
          level: ['info', 'warn', 'error', 'critical'][Math.floor(Math.random() * 4)],
          eventType: ['message_inbound', 'tool_invocation', 'threat_detected', 'policy_decision'][Math.floor(Math.random() * 4)],
          message: `Sample log entry ${i + 1}`,
          data: { sample: true },
        }));
      },
      getStats: async () => ({
        totalEvents: 1247,
        byType: {
          message_inbound: 523,
          message_outbound: 412,
          tool_invocation: 189,
          threat_detected: 23,
          policy_decision: 78,
          enclave_request: 12,
          secret_detected: 10,
        },
        byLevel: {
          info: 980,
          warn: 215,
          error: 42,
          critical: 10,
        },
        threatCount: 23,
      }),
      searchLogs: async (query: string, limit: number) => {
        const logs = await createMockGuard().audit.getRecentLogs({ limit });
        return logs.filter((l: any) => 
          JSON.stringify(l).toLowerCase().includes(query.toLowerCase())
        );
      },
    },
    policy: {
      getConfig: () => ({
        shield: {
          enabled: true,
          sensitivity: 'medium',
          actions: {
            onLow: 'allow',
            onMedium: 'warn',
            onHigh: 'block',
            onCritical: 'block',
          },
        },
        scanner: {
          enabled: true,
          scanOnStartup: true,
          extensions: ['.md', '.yaml', '.json', '.env'],
          excludePaths: ['node_modules/', '.git/'],
          actions: {
            onRead: 'warn',
            onWrite: 'block',
            onExisting: 'report',
          },
        },
        enclave: {
          enabled: true,
          path: '~/.openclaw/enclave',
          protectedFiles: ['SOUL.md', 'IDENTITY.md'],
        },
        channels: {
          whatsapp: {
            allowUnknown: true,
            quarantineUnknown: false,
            rateLimit: { maxPerHour: 100, maxPerDay: 1000 },
          },
          discord: {
            allowUnknown: true,
            quarantineUnknown: false,
          },
        },
        tools: {
          exec: {
            enabled: true,
            requiresApproval: false,
            blockedPatterns: ['rm -rf', 'sudo'],
          },
          message: {
            enabled: true,
            requiresApproval: false,
          },
        },
        audit: {
          enabled: true,
          logPath: '~/.openclaw/logs/clawguard',
          retentionDays: 30,
          logLevel: 'standard',
        },
      }),
      updateConfig: (config: any) => config,
      validate: (config: any) => ({ valid: true, errors: [] }),
    },
    enclave: {
      listFiles: async () => [
        {
          name: 'SOUL.md',
          path: 'SOUL.md',
          hash: 'abc123',
          lastModified: new Date(),
          summary: 'Defines agent personality and boundaries',
        },
        {
          name: 'IDENTITY.md',
          path: 'IDENTITY.md',
          hash: 'def456',
          lastModified: new Date(),
          summary: 'Agent name and core identity',
        },
      ],
      getPendingRequests: () => [
        {
          id: 'req_sample_1',
          file: 'SOUL.md',
          diff: '--- SOUL.md\n+++ SOUL.md\n@@ -1 @@\n-old line\n+new line',
          reason: 'Updating personality traits',
          requestedAt: new Date(Date.now() - 3600000),
          requestedBy: 'agent',
          status: 'pending',
        },
      ],
      checkIntegrity: async () => ({ tampered: [], missing: [] }),
    },
    updateConfig: async (config: any) => config,
  };
}

export const apiRouter = Router();

// Health check
apiRouter.get('/health', (_req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ========== Overview / Stats ==========

apiRouter.get('/stats', async (_req, res) => {
  try {
    const guard = await getGuard();
    const stats = await guard.audit.getStats();
    const pending = guard.enclave.getPendingRequests();
    const integrity = await guard.enclave.checkIntegrity();
    
    res.json({
      ...stats,
      pendingApprovals: pending.length,
      integrityIssues: integrity.tampered.length + integrity.missing.length,
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// ========== Audit Logs ==========

apiRouter.get('/logs', async (req, res) => {
  try {
    const guard = await getGuard();
    const limit = parseInt(req.query.limit as string) || 100;
    const since = req.query.since ? new Date(req.query.since as string) : undefined;
    const eventType = req.query.eventType as string | undefined;
    
    let logs = await guard.audit.getRecentLogs({ limit: limit * 2, since });
    
    if (eventType) {
      logs = logs.filter((l: any) => l.eventType === eventType);
    }
    
    res.json(logs.slice(0, limit));
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch logs' });
  }
});

apiRouter.get('/logs/search', async (req, res) => {
  try {
    const guard = await getGuard();
    const query = req.query.q as string || '';
    const limit = parseInt(req.query.limit as string) || 50;
    
    const logs = await guard.audit.searchLogs(query, limit);
    res.json(logs);
  } catch (error) {
    res.status(500).json({ error: 'Failed to search logs' });
  }
});

// ========== Policies ==========

apiRouter.get('/policies', async (_req, res) => {
  try {
    const guard = await getGuard();
    const config = guard.policy.getConfig();
    res.json(config);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch policies' });
  }
});

apiRouter.put('/policies', async (req, res) => {
  try {
    const guard = await getGuard();
    const config = req.body;
    
    const validation = guard.policy.validate(config);
    if (!validation.valid) {
      res.status(400).json({ error: 'Invalid config', errors: validation.errors });
      return;
    }
    
    await guard.updateConfig(config);
    res.json({ success: true, config: guard.policy.getConfig() });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update policies' });
  }
});

apiRouter.get('/policies/:section', async (req, res) => {
  try {
    const guard = await getGuard();
    const config = guard.policy.getConfig();
    const section = req.params.section as keyof typeof config;
    
    if (!(section in config)) {
      res.status(404).json({ error: 'Section not found' });
      return;
    }
    
    res.json(config[section]);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch policy section' });
  }
});

// ========== Enclave ==========

apiRouter.get('/enclave/files', async (_req, res) => {
  try {
    const guard = await getGuard();
    const files = await guard.enclave.listFiles();
    res.json(files);
  } catch (error) {
    res.status(500).json({ error: 'Failed to list enclave files' });
  }
});

apiRouter.get('/enclave/pending', async (_req, res) => {
  try {
    const guard = await getGuard();
    const pending = guard.enclave.getPendingRequests();
    res.json(pending);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch pending requests' });
  }
});

apiRouter.post('/enclave/approve/:requestId', async (req, res) => {
  try {
    const guard = await getGuard();
    const { requestId } = req.params;
    const { approved } = req.body;
    
    let result;
    if (approved) {
      result = await guard.enclave.approveRequest(requestId, 'dashboard-user');
    } else {
      result = await guard.enclave.denyRequest(requestId, 'dashboard-user');
    }
    
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: 'Failed to process approval' });
  }
});

apiRouter.get('/enclave/integrity', async (_req, res) => {
  try {
    const guard = await getGuard();
    const result = await guard.enclave.checkIntegrity();
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: 'Failed to check integrity' });
  }
});
