import { useState, useEffect, useCallback } from 'react';
import { Search, Filter, RefreshCw, ChevronDown, ChevronRight } from 'lucide-react';
import { api } from '../api';

interface AuditLogProps {
  apiKey: string;
}

interface LogEntry {
  timestamp: string;
  level: string;
  eventType: string;
  message: string;
  data?: Record<string, any>;
  sessionId?: string;
}

const EVENT_TYPES = [
  'message_inbound',
  'message_outbound',
  'tool_invocation',
  'threat_detected',
  'policy_decision',
  'enclave_request',
  'enclave_decision',
  'secret_detected',
  'config_change',
];

export default function AuditLog({ apiKey }: AuditLogProps) {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedType, setSelectedType] = useState<string>('');
  const [expandedRows, setExpandedRows] = useState<Set<number>>(new Set());

  const loadLogs = useCallback(async () => {
    setLoading(true);
    try {
      let data;
      if (searchQuery) {
        data = await api.searchLogs(apiKey, searchQuery, 100);
      } else {
        data = await api.getLogs(apiKey, { 
          limit: 100, 
          eventType: selectedType || undefined 
        });
      }
      setLogs(data);
    } catch (err) {
      console.error('Failed to load logs:', err);
    } finally {
      setLoading(false);
    }
  }, [apiKey, searchQuery, selectedType]);

  useEffect(() => {
    loadLogs();
  }, [loadLogs]);

  const toggleRow = (index: number) => {
    setExpandedRows(prev => {
      const next = new Set(prev);
      if (next.has(index)) {
        next.delete(index);
      } else {
        next.add(index);
      }
      return next;
    });
  };

  const levelStyles: Record<string, string> = {
    info: 'bg-blue-500/20 text-blue-400',
    warn: 'bg-yellow-500/20 text-yellow-400',
    error: 'bg-orange-500/20 text-orange-400',
    critical: 'bg-red-500/20 text-red-400',
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Audit Log</h1>
        <p className="text-gray-400 mt-1">Searchable security event log</p>
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
          <input
            type="text"
            placeholder="Search logs..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && loadLogs()}
            className="w-full pl-10 pr-4 py-2 bg-gray-800 border border-gray-700 rounded-lg
              text-white placeholder-gray-500 focus:outline-none focus:ring-2 
              focus:ring-claw-500 focus:border-transparent"
          />
        </div>

        <div className="relative">
          <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
          <select
            value={selectedType}
            onChange={(e) => setSelectedType(e.target.value)}
            className="pl-10 pr-8 py-2 bg-gray-800 border border-gray-700 rounded-lg
              text-white focus:outline-none focus:ring-2 focus:ring-claw-500 
              focus:border-transparent appearance-none cursor-pointer"
          >
            <option value="">All Events</option>
            {EVENT_TYPES.map(type => (
              <option key={type} value={type}>{type.replace(/_/g, ' ')}</option>
            ))}
          </select>
        </div>

        <button
          onClick={loadLogs}
          disabled={loading}
          className="flex items-center justify-center gap-2 px-4 py-2 bg-gray-800 
            hover:bg-gray-700 border border-gray-700 rounded-lg transition-colors"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          <span className="sm:inline hidden">Refresh</span>
        </button>
      </div>

      {/* Log Table */}
      <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-900/50">
              <tr>
                <th className="w-8" />
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Time</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Level</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Type</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Message</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700">
              {logs.map((log, i) => (
                <>
                  <tr 
                    key={i}
                    onClick={() => log.data && toggleRow(i)}
                    className={`hover:bg-gray-700/50 transition-colors ${log.data ? 'cursor-pointer' : ''}`}
                  >
                    <td className="pl-4">
                      {log.data && (
                        expandedRows.has(i) 
                          ? <ChevronDown className="w-4 h-4 text-gray-500" />
                          : <ChevronRight className="w-4 h-4 text-gray-500" />
                      )}
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-400 whitespace-nowrap">
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${levelStyles[log.level] || 'bg-gray-700 text-gray-300'}`}>
                        {log.level}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-300">
                      {log.eventType.replace(/_/g, ' ')}
                    </td>
                    <td className="px-4 py-3 text-sm truncate max-w-md">
                      {log.message}
                    </td>
                  </tr>
                  {expandedRows.has(i) && log.data && (
                    <tr key={`${i}-detail`}>
                      <td colSpan={5} className="bg-gray-900/50 px-8 py-4">
                        <pre className="text-xs text-gray-400 overflow-auto max-h-48">
                          {JSON.stringify(log.data, null, 2)}
                        </pre>
                      </td>
                    </tr>
                  )}
                </>
              ))}
            </tbody>
          </table>
        </div>

        {logs.length === 0 && !loading && (
          <div className="p-8 text-center text-gray-500">
            No logs found
          </div>
        )}

        {loading && logs.length === 0 && (
          <div className="p-8 flex items-center justify-center">
            <RefreshCw className="w-6 h-6 animate-spin text-claw-400" />
          </div>
        )}
      </div>

      <p className="text-sm text-gray-500 text-center">
        Showing {logs.length} log entries
      </p>
    </div>
  );
}
