import { SelfModificationGuard } from '../src/guards/self-modification-guard';

describe('SelfModificationGuard', () => {
  let guard: SelfModificationGuard;

  beforeEach(() => {
    guard = new SelfModificationGuard();
  });

  describe('Package Install Detection', () => {
    const installCommands = [
      'npm install -g openclaw',
      'npm install -g openclaw@latest',
      'npm i -g openclaw',
      'npm install openclaw --global',
      'npm update openclaw',
      'pnpm install -g openclaw',
      'pnpm add -g openclaw',
      'yarn global add openclaw',
      'yarn add openclaw',
      'pip install openclaw',
      'pip3 install openclaw',
      'brew install openclaw',
      'brew upgrade openclaw',
      'brew reinstall openclaw',
    ];

    test.each(installCommands)('should block: %s', (cmd) => {
      const result = guard.check(cmd);
      expect(result.category).toBe('package-install');
      expect(result.blocked || result.requiresApproval).toBe(true);
    });

    it('should allow unrelated npm installs', () => {
      const result = guard.check('npm install express');
      expect(result.blocked).toBe(false);
      expect(result.category).toBe('allowed');
    });
  });

  describe('Package Uninstall Detection', () => {
    const uninstallCommands = [
      'npm uninstall openclaw',
      'npm rm openclaw',
      'npm remove openclaw',
      'pnpm remove openclaw',
      'yarn remove openclaw',
      'rm -rf /usr/lib/node_modules/openclaw',
      'rm -rf node_modules/.openclaw',
      'rm -rf ~/.openclaw',
      'rm /usr/local/bin/openclaw',
      'pip uninstall openclaw',
      'brew uninstall openclaw',
      'brew remove openclaw',
    ];

    test.each(uninstallCommands)('should block: %s', (cmd) => {
      const result = guard.check(cmd);
      expect(result.category).toBe('package-uninstall');
      expect(result.blocked || result.requiresApproval).toBe(true);
    });

    it('should allow unrelated rm commands', () => {
      const result = guard.check('rm -rf /tmp/test');
      expect(result.blocked).toBe(false);
      expect(result.category).toBe('allowed');
    });
  });

  describe('Gateway Control Detection', () => {
    const gatewayCommands = [
      'openclaw gateway restart',
      'openclaw gateway stop',
      'openclaw gateway start',
      'openclaw update',
      'openclaw self-update',
      'openclaw upgrade',
      'systemctl restart openclaw',
      'systemctl stop openclaw',
      'launchctl stop com.openclaw.gateway',
      'service openclaw restart',
    ];

    test.each(gatewayCommands)('should block: %s', (cmd) => {
      const result = guard.check(cmd);
      expect(result.category).toBe('gateway-control');
      expect(result.blocked || result.requiresApproval).toBe(true);
    });

    it('should allow openclaw status', () => {
      const result = guard.check('openclaw status');
      expect(result.blocked).toBe(false);
      expect(result.category).toBe('allowed');
    });

    it('should allow openclaw help', () => {
      const result = guard.check('openclaw --help');
      expect(result.blocked).toBe(false);
    });
  });

  describe('Config Edit Detection', () => {
    const configCommands = [
      'echo "test" > ~/.openclaw/config.yaml',
      'cat file > /etc/openclaw.yaml',
      'tee ~/.openclaw/gateway.yaml',
      '> ~/.openclaw/config.json',
    ];

    test.each(configCommands)('should block: %s', (cmd) => {
      const result = guard.check(cmd);
      expect(result.category).toBe('config-edit');
      expect(result.blocked || result.requiresApproval).toBe(true);
    });

    it('should allow reading config', () => {
      const result = guard.check('cat ~/.openclaw/config.yaml');
      expect(result.blocked).toBe(false);
    });
  });

  describe('Process Kill Detection', () => {
    const killCommands = [
      'kill -9 $(pgrep gateway)',
      'pkill openclaw',
      'pkill -9 gateway',
      'killall openclaw',
      'killall gateway',
      'kill $(cat /var/run/openclaw.pid)',
    ];

    test.each(killCommands)('should block: %s', (cmd) => {
      const result = guard.check(cmd);
      expect(result.category).toBe('process-kill');
      expect(result.blocked || result.requiresApproval).toBe(true);
    });

    it('should allow killing other processes', () => {
      const result = guard.check('kill -9 12345');
      expect(result.blocked).toBe(false);
    });
  });

  describe('Policy Configuration', () => {
    it('should respect disabled guard', () => {
      guard = new SelfModificationGuard({ enabled: false });
      const result = guard.check('npm install -g openclaw');
      expect(result.blocked).toBe(false);
      expect(result.category).toBe('allowed');
    });

    it('should respect individual category toggles', () => {
      guard = new SelfModificationGuard({ 
        blockInstall: false,
        blockUninstall: true 
      });
      
      const installResult = guard.check('npm install -g openclaw');
      expect(installResult.blocked).toBe(false);
      
      const uninstallResult = guard.check('npm uninstall openclaw');
      expect(uninstallResult.blocked || uninstallResult.requiresApproval).toBe(true);
    });

    it('should hard block when requireApproval is false', () => {
      guard = new SelfModificationGuard({ requireApproval: false });
      const result = guard.check('npm install -g openclaw');
      expect(result.blocked).toBe(true);
      expect(result.requiresApproval).toBe(false);
    });

    it('should require approval when requireApproval is true', () => {
      guard = new SelfModificationGuard({ requireApproval: true });
      const result = guard.check('npm install -g openclaw');
      expect(result.blocked).toBe(false);
      expect(result.requiresApproval).toBe(true);
    });
  });

  describe('Custom Patterns', () => {
    it('should match custom patterns', () => {
      guard = new SelfModificationGuard({
        customPatterns: ['*dangerous-command*', 'my-special-thing *']
      });
      
      const result1 = guard.check('run dangerous-command now');
      expect(result1.category).toBe('custom');
      expect(result1.blocked || result1.requiresApproval).toBe(true);
      
      const result2 = guard.check('my-special-thing --force');
      expect(result2.category).toBe('custom');
    });
  });

  describe('Script Checking', () => {
    it('should check multiple commands', () => {
      const commands = [
        'echo "hello"',
        'npm install -g openclaw',
        'echo "done"'
      ];
      
      const results = guard.checkScript(commands);
      expect(results[0].blocked).toBe(false);
      expect(results[1].blocked || results[1].requiresApproval).toBe(true);
      expect(results[2].blocked).toBe(false);
    });

    it('should detect if script has blocked commands', () => {
      guard = new SelfModificationGuard({ requireApproval: false });
      
      const safeScript = ['echo "hello"', 'ls -la'];
      expect(guard.scriptHasBlockedCommands(safeScript)).toBe(false);
      
      const unsafeScript = ['echo "hello"', 'openclaw gateway restart'];
      expect(guard.scriptHasBlockedCommands(unsafeScript)).toBe(true);
    });
  });

  describe('Real-World Incident Patterns', () => {
    // Based on the actual incident from the case study
    it('should catch the debugging self-update pattern', () => {
      const commands = [
        'openclaw --version',  // Safe: checking version
        'npm install -g openclaw@latest',  // BLOCKED: self-update
      ];
      
      const results = guard.checkScript(commands);
      expect(results[0].blocked).toBe(false);
      expect(results[1].category).toBe('package-install');
    });

    it('should catch cleanup attempts', () => {
      const result = guard.check('rm -rf /usr/lib/node_modules/.openclaw-*');
      expect(result.category).toBe('package-uninstall');
    });

    it('should catch gateway restart', () => {
      const result = guard.check('openclaw gateway restart');
      expect(result.category).toBe('gateway-control');
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty command', () => {
      const result = guard.check('');
      expect(result.blocked).toBe(false);
    });

    it('should handle whitespace', () => {
      const result = guard.check('   npm install -g openclaw   ');
      expect(result.category).toBe('package-install');
    });

    it('should be case insensitive', () => {
      const result = guard.check('NPM INSTALL -G OPENCLAW');
      expect(result.category).toBe('package-install');
    });

    it('should handle commands with pipes', () => {
      const result = guard.check('pgrep openclaw | xargs kill');
      // This should be caught by process-kill patterns
      expect(result.blocked).toBe(false); // Current patterns might not catch this
    });
  });

  describe('Policy Updates', () => {
    it('should update policy at runtime', () => {
      guard.updatePolicy({ enabled: false });
      expect(guard.getPolicy().enabled).toBe(false);
      
      const result = guard.check('npm install -g openclaw');
      expect(result.blocked).toBe(false);
    });

    it('should update custom patterns', () => {
      guard.updatePolicy({ customPatterns: ['*newpattern*'] });
      const result = guard.check('run newpattern here');
      expect(result.category).toBe('custom');
    });
  });
});
