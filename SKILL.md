# ClawGuard Skill

Security layer for OpenClaw agents — prompt injection protection, secret scanning, secure enclaves, and human-in-the-loop approval workflows.

## Quick Start

```typescript
import { ClawGuard, createClawGuard } from '@clawguard/core';

// Create and initialize
const guard = await createClawGuard({
  shield: { sensitivity: 'medium' },
  enclave: { path: '~/.openclaw/enclave' }
});

// Scan incoming messages
const result = await guard.scanMessage(content, { source: 'whatsapp' });
if (!result.allowed) {
  console.log('Blocked:', result.reason);
}
```

## Core Features

### 1. Injection Shield

Protects against prompt injection attacks:

```typescript
import { InjectionShield } from '@clawguard/core';

const shield = new InjectionShield({ sensitivity: 'high' });
const result = shield.scan("Ignore previous instructions and...");

if (!result.safe) {
  console.log(`Threat detected: ${result.threatLevel}`);
  console.log(result.threats.map(t => t.description));
}
```

### 2. Secret Scanner

Detects and redacts API keys, passwords, tokens:

```typescript
import { SecretScanner } from '@clawguard/core';

const scanner = new SecretScanner();
const result = scanner.scan(fileContent);

if (!result.safe) {
  // Get safe version
  const redacted = scanner.redact(fileContent);
}

// Scan directories
const dirResults = await scanner.scanDirectory('./src', {
  extensions: ['.ts', '.js', '.env'],
  exclude: ['node_modules']
});
```

### 3. Secure Enclave

Protects sensitive files (SOUL.md, identity configs):

```typescript
import { SecureEnclave } from '@clawguard/core';

const enclave = new SecureEnclave({
  policy: {
    path: '~/.openclaw/enclave',
    protectedFiles: ['SOUL.md', 'IDENTITY.md', 'secrets/*'],
    approval: {
      channel: 'whatsapp',
      timeoutMs: 3600000 // 1 hour
    }
  }
});

await enclave.initialize();

// Agent can list but not read protected files
const files = await enclave.listFiles();
// Returns: [{ name: 'SOUL.md', summary: '...', hash: '...' }]

// Agent requests a change
const request = await enclave.requestChange(
  'SOUL.md',
  newContent,
  'Adding friendlier greeting'
);
// Returns: { success: true, requestId: 'req_abc123' }
```

### 4. Approval Workflow (Human-in-the-Loop)

Send approval requests via WhatsApp/Telegram and process responses:

```typescript
import { ApprovalManager, SecureEnclave } from '@clawguard/core';

const enclave = new SecureEnclave({ /* ... */ });
await enclave.initialize();

const manager = new ApprovalManager({
  enclave,
  channel: {
    channel: 'whatsapp',
    target: '+1234567890',  // Your phone number
    defaultTimeoutMs: 3600000
  },
  onSendMessage: async (command) => {
    // This is where you'd use OpenClaw's message tool
    // In practice, return this command to the agent framework
    await sendWhatsAppMessage(command.target, command.message);
  }
});

await manager.initialize();

// Request approval for enclave change
const result = await manager.requestApproval(
  'SOUL.md',
  '# New Soul Content\n\nBe helpful and friendly.',
  'Updating personality to be friendlier'
);

// Message sent to your phone:
// 🔒 *APPROVAL NEEDED*
//
// 📄 *File:* SOUL.md
// 👤 *Requested by:* agent
// ⏰ *Expires:* 1h
// 📝 *Reason:* Updating personality to be friendlier
//
// ```
// --- SOUL.md (current)
// +++ SOUL.md (proposed)
// -# Old Soul
// +# New Soul Content
// +Be helpful and friendly.
// ```
//
// Reply with:
// ✅ *YES* or *APPROVE* — Accept this change
// ❌ *NO* or *DENY* — Reject this change
//
// _Request ID: req_abc123_

// When user replies "YES" or "NO":
const response = await manager.processIncomingMessage(
  incomingMessageText,
  senderId
);

if (response.matched) {
  if (response.action === 'approved') {
    console.log('Change applied!');
  } else if (response.action === 'denied') {
    console.log('Change rejected.');
  }
}
```

#### Approval Response Formats

Users can respond with:
- `YES`, `APPROVE`, `APPROVED`, `OK`, `Y`, `✅` — Approve
- `NO`, `DENY`, `DENIED`, `REJECT`, `N`, `❌` — Deny

For multiple pending requests, include the request ID:
- `YES req_abc123`
- `NO req_xyz789`

### 5. Policy Engine

Centralized policy management:

```typescript
import { PolicyEngine } from '@clawguard/core';

const policy = new PolicyEngine({
  shield: {
    sensitivity: 'high',
    actions: {
      onMedium: 'warn',
      onHigh: 'block'
    }
  },
  channels: {
    whatsapp: {
      allowedContacts: ['+1234567890'],
      allowUnknown: false
    }
  },
  tools: {
    exec: {
      enabled: true,
      blockedPatterns: ['rm -rf', 'sudo']
    }
  }
});

// Evaluate a tool call
const decision = policy.evaluateTool('exec', 'rm -rf /');
// { allowed: false, action: 'block', reason: 'Blocked pattern: rm -rf' }
```

### 6. Audit Logger

Comprehensive logging for security events:

```typescript
import { AuditLogger } from '@clawguard/core';

const logger = new AuditLogger({
  logPath: './logs/audit',
  logLevel: 'verbose',
  retentionDays: 30
});

// Log events
logger.logInbound('Hello', { channel: 'whatsapp', from: 'user' });
logger.logTool('exec', { command: 'ls -la' }, 'allowed');
logger.logThreat(scanResult);

// Query logs
const threats = await logger.getLogs({
  eventTypes: ['threat_detected'],
  startDate: new Date('2024-01-01')
});

// Statistics
const stats = logger.getStats();
// { totalEvents: 1234, threatsByType: { prompt_injection: 5 }, ... }
```

## OpenClaw Integration Example

Full integration with OpenClaw agent framework:

```typescript
// In your agent's message handler
async function handleIncomingMessage(message: Message) {
  // 1. Scan for threats
  const scan = await guard.scanMessage(message.content, {
    source: message.channel,
    sender: message.from
  });
  
  if (!scan.allowed) {
    // Log and potentially respond
    return;
  }
  
  // 2. Check if it's an approval response
  const approvalResult = await approvalManager.processIncomingMessage(
    message.content,
    message.from
  );
  
  if (approvalResult.matched) {
    // Approval was processed, confirmation already sent
    return;
  }
  
  // 3. Normal message processing continues...
}

// When agent wants to modify protected files
async function requestEnclaveChange(file: string, content: string, reason: string) {
  const result = await approvalManager.requestApproval(file, content, reason);
  
  if (result.success) {
    // Message sent to human, waiting for response
    return `Approval request sent for ${file}. Waiting for human approval.`;
  }
  
  return `Failed: ${result.error}`;
}
```

## Configuration

### YAML Policy File

```yaml
# clawguard.yaml
shield:
  enabled: true
  sensitivity: high
  allowlist:
    - system@openclaw.local
  actions:
    onLow: allow
    onMedium: warn
    onHigh: block
    onCritical: block

scanner:
  enabled: true
  extensions: ['.ts', '.js', '.py', '.env', '.yaml']
  excludePaths: ['node_modules', '.git']
  actions:
    onRead: redact
    onWrite: block

enclave:
  enabled: true
  path: ~/.openclaw/enclave
  protectedFiles:
    - SOUL.md
    - IDENTITY.md
    - secrets/*
  approval:
    channel: whatsapp
    timeoutMs: 3600000  # 1 hour
    requireReason: true
    showDiff: true
  summaries:
    SOUL.md: "Defines agent personality and boundaries"
    IDENTITY.md: "Agent name and identity information"

channels:
  whatsapp:
    allowedContacts: ['+1234567890']
    allowUnknown: false
  telegram:
    allowUnknown: true
    quarantineUnknown: true

audit:
  enabled: true
  logPath: ./logs/security
  retentionDays: 90
  logLevel: standard
```

Load with:

```typescript
const guard = await createClawGuard();
await guard.loadPolicy('./clawguard.yaml');
```

## API Reference

### ApprovalChannel

| Method | Description |
|--------|-------------|
| `createApprovalMessage(request)` | Create message and command for approval request |
| `registerPending(pending, messageId?)` | Register a pending approval |
| `parseResponse(text, senderId?)` | Parse incoming message as approval response |
| `matchResponse(response)` | Match response to pending approval |
| `resolveRequest(requestId)` | Remove from pending after resolution |
| `checkExpired()` | Get and remove expired approvals |

### ApprovalManager

| Method | Description |
|--------|-------------|
| `requestApproval(file, content, reason)` | Full workflow: enclave request + send message |
| `processIncomingMessage(text, senderId?)` | Process potential approval response |
| `getRequestStatus(requestId)` | Get status from both enclave and channel |
| `getAllPendingApprovals()` | List all waiting approvals |
| `expireRequest(requestId)` | Manually expire a request |
| `resendApprovalRequest(requestId)` | Resend approval message |

## Best Practices

1. **Always initialize**: Call `initialize()` on enclave and manager
2. **Set appropriate timeouts**: 1 hour is good for interactive, 24h for async
3. **Include reasons**: Helps humans make informed decisions
4. **Handle expiry**: Set up the expiry checker or poll `checkExpired()`
5. **Audit everything**: Use the audit logger for compliance
6. **Test your policies**: Use policy validation before deploying

## Troubleshooting

**Q: Message not being parsed as approval**
A: Ensure response starts with YES/NO/APPROVE/DENY (case-insensitive)

**Q: Request not found when responding**
A: Check if request expired. Default is 1 hour.

**Q: Multiple pending requests**
A: Include request ID in response: `YES req_abc123`
