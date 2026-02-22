# ClawGuard Plugin Development Plan

## Goal
Make ClawGuard installable with one command:
```bash
openclaw plugins install @moltpill/clawguard
```

---

## Phase 1: Plugin Wrapper Package ⏳
**Estimated: 1-2 days**

### Create `@moltpill/clawguard-openclaw` package

```
packages/
├── core/                 # Existing @moltpill/clawguard
└── openclaw-plugin/      # NEW: OpenClaw plugin wrapper
    ├── package.json
    ├── src/
    │   ├── index.ts      # Plugin entry point
    │   ├── hooks/
    │   │   ├── message-shield.ts
    │   │   ├── tool-guard.ts
    │   │   └── file-watch.ts
    │   └── config.ts     # OpenClaw config integration
    └── openclaw.plugin.json
```

### Tasks
- [ ] Create plugin package structure
- [ ] Define `openclaw.plugin.json` manifest
- [ ] Export plugin entry point with `register()` function
- [ ] Import core ClawGuard components

---

## Phase 2: Hook Integration ⏳
**Estimated: 2-3 days**

### Message Hook (`message:before`)
```typescript
api.registerHook("message:before", async (ctx) => {
  const result = shield.scan(ctx.message.content, {
    channel: ctx.channel.id,
    senderId: ctx.message.senderId,
    isExternal: ctx.message.isExternal,
  });
  
  if (result.action === "block") {
    throw new Error("Message blocked by ClawGuard");
  }
  
  return ctx;
});
```

### Tool Hook (`tool:before`)
```typescript
api.registerHook("tool:before", async (ctx) => {
  // Check self-modification first
  if (ctx.tool.name === 'exec') {
    const selfModCheck = selfMod.check(ctx.args.command);
    if (selfModCheck.blocked) {
      throw new Error(`Blocked: ${selfModCheck.reason}`);
    }
  }
  
  // Check policy
  const check = policy.checkTool(ctx.tool.name, ctx.tool.action, ctx.args);
  if (!check.allowed) {
    if (check.requiresApproval) {
      return api.requestApproval({ ... });
    }
    throw new Error(`Tool blocked: ${check.reason}`);
  }
  
  return ctx;
});
```

### File Hook (`file:before`)
```typescript
api.registerHook("file:before", async (ctx) => {
  if (ctx.operation !== "write") return ctx;
  
  // Check enclave
  if (enclave.isProtected(ctx.path)) {
    return api.requestApproval({
      operation: "enclave-write",
      path: ctx.path,
    });
  }
  
  // Scan for secrets
  const scan = scanner.scanContent(ctx.content);
  if (!scan.safe) {
    throw new Error(`Secret detected in file write`);
  }
  
  return ctx;
});
```

### Tasks
- [ ] Implement message:before hook
- [ ] Implement tool:before hook with SelfModificationGuard
- [ ] Implement file:before hook with enclave + scanner
- [ ] Add approval workflow integration
- [ ] Test each hook in isolation

---

## Phase 3: Config Integration ⏳
**Estimated: 1 day**

### OpenClaw Config Schema
```yaml
# In user's openclaw config
plugins:
  clawguard:
    shield:
      enabled: true
      sensitivity: medium
    scanner:
      enabled: true
    enclave:
      protectedFiles:
        - SOUL.md
        - USER.md
        - MEMORY.md
        - secrets/*
    selfModification:
      enabled: true
      requireApproval: true
    audit:
      enabled: true
```

### Tasks
- [ ] Define Zod schema for config validation
- [ ] Integrate with OpenClaw's config system
- [ ] Auto-detect workspace files for enclave
- [ ] Set sensible defaults

---

## Phase 4: CLI Subcommands ⏳
**Estimated: 1 day**

### Register with OpenClaw CLI
```typescript
api.registerCli(({ program }) => {
  const cmd = program.command("clawguard");
  
  cmd.command("status").action(showStatus);
  cmd.command("level <level>").action(setLevel);
  cmd.command("scan <path>").action(scanPath);
  cmd.command("logs").action(showLogs);
});
```

### Tasks
- [ ] Register CLI commands via plugin API
- [ ] Migrate existing CLI logic
- [ ] Add `openclaw clawguard` namespace

---

## Phase 5: Setup Wizard (Optional) ⏳
**Estimated: 1 day**

### Interactive Setup
```bash
npx @moltpill/clawguard-setup
```

- Asks about security preferences
- Scans workspace for existing secrets
- Installs plugin automatically
- Creates custom config

### Tasks
- [ ] Create setup package
- [ ] Interactive prompts (inquirer)
- [ ] Initial workspace scan
- [ ] Generate config file

---

## Phase 6: Publish & Document ⏳
**Estimated: 1 day**

### Publish to npm
```bash
cd packages/core
npm publish --access public

cd packages/openclaw-plugin
npm publish --access public
```

### Documentation
- [ ] Update README with plugin install instructions
- [ ] Add to OpenClaw community plugins list
- [ ] Create video demo (optional)

---

## Success Criteria

User can run:
```bash
openclaw plugins install @moltpill/clawguard
```

And immediately have:
- ✅ Injection scanning on all messages
- ✅ Tool policy enforcement
- ✅ Secret leak prevention
- ✅ Enclave protection for identity files
- ✅ Self-modification guard active
- ✅ Audit logging enabled

No manual config required (sensible defaults).

---

## Dependencies

- OpenClaw plugin SDK (need to verify API)
- Core ClawGuard package
- Zod for config validation

---

## Open Questions

1. **OpenClaw Plugin API** — Need to verify exact hook names and signatures
2. **Approval Workflow** — How does OpenClaw handle approval requests?
3. **Config Location** — Where does OpenClaw store plugin configs?
4. **CLI Registration** — Exact API for registering subcommands?

→ May need to check OpenClaw docs or source code for answers.

---

## Timeline

| Phase | Task | Days | Status |
|-------|------|------|--------|
| 1 | Plugin Wrapper | 1-2 | ⏳ Ready to start |
| 2 | Hook Integration | 2-3 | ⏳ |
| 3 | Config Integration | 1 | ⏳ |
| 4 | CLI Subcommands | 1 | ⏳ |
| 5 | Setup Wizard | 1 | ⏳ Optional |
| 6 | Publish & Docs | 1 | ⏳ |

**Total: ~7-9 days to production-ready plugin**

---

*Last updated: 2026-02-22*
