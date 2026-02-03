import { useState, useEffect } from 'react';
import { Save, RefreshCw, Shield, Eye, Lock, ScrollText, MessageSquare, Wrench } from 'lucide-react';
import { api } from '../api';

interface PoliciesProps {
  apiKey: string;
}

type TabKey = 'shield' | 'scanner' | 'enclave' | 'channels' | 'tools' | 'audit';

const tabs: { key: TabKey; label: string; icon: any }[] = [
  { key: 'shield', label: 'Shield', icon: Shield },
  { key: 'scanner', label: 'Scanner', icon: Eye },
  { key: 'enclave', label: 'Enclave', icon: Lock },
  { key: 'channels', label: 'Channels', icon: MessageSquare },
  { key: 'tools', label: 'Tools', icon: Wrench },
  { key: 'audit', label: 'Audit', icon: ScrollText },
];

export default function Policies({ apiKey }: PoliciesProps) {
  const [config, setConfig] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [activeTab, setActiveTab] = useState<TabKey>('shield');
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const loadPolicies = async () => {
    setLoading(true);
    try {
      const data = await api.getPolicies(apiKey);
      setConfig(data);
    } catch (err) {
      setMessage({ type: 'error', text: 'Failed to load policies' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadPolicies();
  }, [apiKey]);

  const handleSave = async () => {
    setSaving(true);
    try {
      await api.updatePolicies(apiKey, config);
      setMessage({ type: 'success', text: 'Policies saved successfully' });
      setTimeout(() => setMessage(null), 3000);
    } catch (err) {
      setMessage({ type: 'error', text: 'Failed to save policies' });
    } finally {
      setSaving(false);
    }
  };

  const updateConfig = (section: TabKey, updates: any) => {
    setConfig((prev: any) => ({
      ...prev,
      [section]: { ...prev[section], ...updates },
    }));
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 animate-spin text-claw-400" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Policies</h1>
          <p className="text-gray-400 mt-1">Configure security policies</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={loadPolicies}
            className="flex items-center gap-2 px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
            Reset
          </button>
          <button
            onClick={handleSave}
            disabled={saving}
            className="flex items-center gap-2 px-4 py-2 bg-claw-500 hover:bg-claw-600 rounded-lg transition-colors"
          >
            <Save className={`w-4 h-4 ${saving ? 'animate-pulse' : ''}`} />
            Save
          </button>
        </div>
      </div>

      {message && (
        <div className={`p-4 rounded-lg ${
          message.type === 'success' ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'
        }`}>
          {message.text}
        </div>
      )}

      {/* Tabs */}
      <div className="border-b border-gray-700">
        <div className="flex gap-1 overflow-x-auto">
          {tabs.map(({ key, label, icon: Icon }) => (
            <button
              key={key}
              onClick={() => setActiveTab(key)}
              className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${
                activeTab === key
                  ? 'border-claw-500 text-claw-400'
                  : 'border-transparent text-gray-400 hover:text-gray-300'
              }`}
            >
              <Icon className="w-4 h-4" />
              {label}
            </button>
          ))}
        </div>
      </div>

      {/* Policy Editor */}
      <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
        {activeTab === 'shield' && config?.shield && (
          <ShieldEditor value={config.shield} onChange={(v) => updateConfig('shield', v)} />
        )}
        {activeTab === 'scanner' && config?.scanner && (
          <ScannerEditor value={config.scanner} onChange={(v) => updateConfig('scanner', v)} />
        )}
        {activeTab === 'enclave' && config?.enclave && (
          <EnclaveEditor value={config.enclave} onChange={(v) => updateConfig('enclave', v)} />
        )}
        {activeTab === 'channels' && config?.channels && (
          <ChannelsEditor value={config.channels} onChange={(v) => setConfig((p: any) => ({ ...p, channels: v }))} />
        )}
        {activeTab === 'tools' && config?.tools && (
          <ToolsEditor value={config.tools} onChange={(v) => setConfig((p: any) => ({ ...p, tools: v }))} />
        )}
        {activeTab === 'audit' && config?.audit && (
          <AuditEditor value={config.audit} onChange={(v) => updateConfig('audit', v)} />
        )}
      </div>
    </div>
  );
}

// Policy Section Editors

function ShieldEditor({ value, onChange }: { value: any; onChange: (v: any) => void }) {
  return (
    <div className="space-y-6">
      <Toggle label="Enabled" checked={value.enabled} onChange={(v) => onChange({ enabled: v })} />
      
      <Select
        label="Sensitivity"
        value={value.sensitivity}
        options={['low', 'medium', 'high']}
        onChange={(v) => onChange({ sensitivity: v })}
      />

      <div className="grid grid-cols-2 gap-4">
        {['onLow', 'onMedium', 'onHigh', 'onCritical'].map((action) => (
          <Select
            key={action}
            label={action.replace('on', 'On ')}
            value={value.actions[action]}
            options={['allow', 'warn', 'block', 'quarantine', 'require_approval']}
            onChange={(v) => onChange({ actions: { ...value.actions, [action]: v } })}
          />
        ))}
      </div>
    </div>
  );
}

function ScannerEditor({ value, onChange }: { value: any; onChange: (v: any) => void }) {
  return (
    <div className="space-y-6">
      <Toggle label="Enabled" checked={value.enabled} onChange={(v) => onChange({ enabled: v })} />
      <Toggle label="Scan on Startup" checked={value.scanOnStartup} onChange={(v) => onChange({ scanOnStartup: v })} />

      <div className="grid grid-cols-3 gap-4">
        <Select
          label="On Read"
          value={value.actions.onRead}
          options={['allow', 'warn', 'redact', 'block']}
          onChange={(v) => onChange({ actions: { ...value.actions, onRead: v } })}
        />
        <Select
          label="On Write"
          value={value.actions.onWrite}
          options={['allow', 'warn', 'block']}
          onChange={(v) => onChange({ actions: { ...value.actions, onWrite: v } })}
        />
        <Select
          label="On Existing"
          value={value.actions.onExisting}
          options={['report', 'quarantine']}
          onChange={(v) => onChange({ actions: { ...value.actions, onExisting: v } })}
        />
      </div>

      <TextArea
        label="File Extensions"
        value={value.extensions?.join(', ') || ''}
        onChange={(v) => onChange({ extensions: v.split(',').map((s: string) => s.trim()).filter(Boolean) })}
        placeholder=".md, .yaml, .json, .env"
      />
    </div>
  );
}

function EnclaveEditor({ value, onChange }: { value: any; onChange: (v: any) => void }) {
  return (
    <div className="space-y-6">
      <Toggle label="Enabled" checked={value.enabled} onChange={(v) => onChange({ enabled: v })} />
      
      <Input
        label="Enclave Path"
        value={value.path}
        onChange={(v) => onChange({ path: v })}
      />

      <TextArea
        label="Protected Files"
        value={value.protectedFiles?.join('\n') || ''}
        onChange={(v) => onChange({ protectedFiles: v.split('\n').map((s: string) => s.trim()).filter(Boolean) })}
        placeholder="SOUL.md&#10;IDENTITY.md&#10;secrets/*"
      />

      <div className="grid grid-cols-2 gap-4">
        <Input
          label="Approval Channel"
          value={value.approval?.channel || ''}
          onChange={(v) => onChange({ approval: { ...value.approval, channel: v } })}
        />
        <Input
          label="Timeout (ms)"
          type="number"
          value={value.approval?.timeoutMs || 86400000}
          onChange={(v) => onChange({ approval: { ...value.approval, timeoutMs: parseInt(v) } })}
        />
      </div>

      <div className="flex gap-6">
        <Toggle
          label="Require Reason"
          checked={value.approval?.requireReason}
          onChange={(v) => onChange({ approval: { ...value.approval, requireReason: v } })}
        />
        <Toggle
          label="Show Diff"
          checked={value.approval?.showDiff}
          onChange={(v) => onChange({ approval: { ...value.approval, showDiff: v } })}
        />
      </div>
    </div>
  );
}

function ChannelsEditor({ value, onChange }: { value: any; onChange: (v: any) => void }) {
  const channels = Object.keys(value);
  
  return (
    <div className="space-y-6">
      {channels.length === 0 && (
        <p className="text-gray-500">No channel policies configured</p>
      )}
      {channels.map((channel) => (
        <div key={channel} className="border border-gray-700 rounded-lg p-4">
          <h3 className="font-medium mb-4 capitalize">{channel}</h3>
          <div className="grid grid-cols-2 gap-4">
            <Toggle
              label="Allow Unknown"
              checked={value[channel].allowUnknown}
              onChange={(v) => onChange({ ...value, [channel]: { ...value[channel], allowUnknown: v } })}
            />
            <Toggle
              label="Quarantine Unknown"
              checked={value[channel].quarantineUnknown}
              onChange={(v) => onChange({ ...value, [channel]: { ...value[channel], quarantineUnknown: v } })}
            />
            {value[channel].rateLimit && (
              <>
                <Input
                  label="Max/Hour"
                  type="number"
                  value={value[channel].rateLimit.maxPerHour}
                  onChange={(v) => onChange({ ...value, [channel]: { ...value[channel], rateLimit: { ...value[channel].rateLimit, maxPerHour: parseInt(v) } } })}
                />
                <Input
                  label="Max/Day"
                  type="number"
                  value={value[channel].rateLimit.maxPerDay}
                  onChange={(v) => onChange({ ...value, [channel]: { ...value[channel], rateLimit: { ...value[channel].rateLimit, maxPerDay: parseInt(v) } } })}
                />
              </>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}

function ToolsEditor({ value, onChange }: { value: any; onChange: (v: any) => void }) {
  const tools = Object.keys(value);
  
  return (
    <div className="space-y-6">
      {tools.length === 0 && (
        <p className="text-gray-500">No tool policies configured</p>
      )}
      {tools.map((tool) => (
        <div key={tool} className="border border-gray-700 rounded-lg p-4">
          <h3 className="font-medium mb-4 font-mono">{tool}</h3>
          <div className="grid grid-cols-2 gap-4">
            <Toggle
              label="Enabled"
              checked={value[tool].enabled}
              onChange={(v) => onChange({ ...value, [tool]: { ...value[tool], enabled: v } })}
            />
            <Toggle
              label="Requires Approval"
              checked={value[tool].requiresApproval}
              onChange={(v) => onChange({ ...value, [tool]: { ...value[tool], requiresApproval: v } })}
            />
          </div>
          {value[tool].blockedPatterns && (
            <div className="mt-4">
              <TextArea
                label="Blocked Patterns"
                value={value[tool].blockedPatterns?.join('\n') || ''}
                onChange={(v) => onChange({ ...value, [tool]: { ...value[tool], blockedPatterns: v.split('\n').filter(Boolean) } })}
              />
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function AuditEditor({ value, onChange }: { value: any; onChange: (v: any) => void }) {
  return (
    <div className="space-y-6">
      <Toggle label="Enabled" checked={value.enabled} onChange={(v) => onChange({ enabled: v })} />
      
      <Input
        label="Log Path"
        value={value.logPath}
        onChange={(v) => onChange({ logPath: v })}
      />

      <div className="grid grid-cols-2 gap-4">
        <Input
          label="Retention Days"
          type="number"
          value={value.retentionDays}
          onChange={(v) => onChange({ retentionDays: parseInt(v) })}
        />
        <Select
          label="Log Level"
          value={value.logLevel}
          options={['minimal', 'standard', 'verbose']}
          onChange={(v) => onChange({ logLevel: v })}
        />
      </div>

      <Toggle
        label="Include Content"
        checked={value.includeContent}
        onChange={(v) => onChange({ includeContent: v })}
      />
    </div>
  );
}

// Form Components

function Toggle({ label, checked, onChange }: { label: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="flex items-center gap-3 cursor-pointer">
      <div className={`w-10 h-6 rounded-full transition-colors ${checked ? 'bg-claw-500' : 'bg-gray-600'}`}>
        <div className={`w-4 h-4 bg-white rounded-full mt-1 transition-transform ${checked ? 'translate-x-5' : 'translate-x-1'}`} />
      </div>
      <span className="text-sm">{label}</span>
    </label>
  );
}

function Select({ label, value, options, onChange }: { label: string; value: string; options: string[]; onChange: (v: string) => void }) {
  return (
    <div>
      <label className="block text-sm text-gray-400 mb-1">{label}</label>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-claw-500"
      >
        {options.map((opt) => (
          <option key={opt} value={opt}>{opt}</option>
        ))}
      </select>
    </div>
  );
}

function Input({ label, value, type = 'text', onChange, placeholder }: { label: string; value: any; type?: string; onChange: (v: string) => void; placeholder?: string }) {
  return (
    <div>
      <label className="block text-sm text-gray-400 mb-1">{label}</label>
      <input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-claw-500"
      />
    </div>
  );
}

function TextArea({ label, value, onChange, placeholder }: { label: string; value: string; onChange: (v: string) => void; placeholder?: string }) {
  return (
    <div>
      <label className="block text-sm text-gray-400 mb-1">{label}</label>
      <textarea
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        rows={3}
        className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-claw-500 resize-none"
      />
    </div>
  );
}
