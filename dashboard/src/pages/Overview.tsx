import { useState, useEffect } from 'react';
import { 
  Activity, 
  AlertTriangle, 
  FileCheck, 
  Shield, 
  Clock,
  RefreshCw
} from 'lucide-react';
import StatCard from '../components/StatCard';
import { api } from '../api';

interface OverviewProps {
  apiKey: string;
}

interface Stats {
  totalEvents: number;
  byType: Record<string, number>;
  byLevel: Record<string, number>;
  threatCount: number;
  pendingApprovals: number;
  integrityIssues: number;
}

interface LogEntry {
  timestamp: string;
  level: string;
  eventType: string;
  message: string;
}

export default function Overview({ apiKey }: OverviewProps) {
  const [stats, setStats] = useState<Stats | null>(null);
  const [recentLogs, setRecentLogs] = useState<LogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const loadData = async () => {
    setLoading(true);
    try {
      const [statsData, logsData] = await Promise.all([
        api.getStats(apiKey),
        api.getLogs(apiKey, { limit: 10 }),
      ]);
      setStats(statsData);
      setRecentLogs(logsData);
      setError('');
    } catch (err) {
      setError('Failed to load data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 30000); // Refresh every 30s
    return () => clearInterval(interval);
  }, [apiKey]);

  const levelColors: Record<string, string> = {
    info: 'text-blue-400',
    warn: 'text-yellow-400',
    error: 'text-orange-400',
    critical: 'text-red-400',
  };

  if (loading && !stats) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 animate-spin text-claw-400" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-500/20 border border-red-500/50 rounded-lg p-4 text-red-400">
        {error}
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Overview</h1>
          <p className="text-gray-400 mt-1">System health and recent activity</p>
        </div>
        <button
          onClick={loadData}
          disabled={loading}
          className="flex items-center gap-2 px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Events"
          value={stats?.totalEvents.toLocaleString() || '0'}
          icon={Activity}
          color="blue"
        />
        <StatCard
          title="Threats Detected"
          value={stats?.threatCount || '0'}
          icon={AlertTriangle}
          color={stats?.threatCount ? 'red' : 'green'}
        />
        <StatCard
          title="Pending Approvals"
          value={stats?.pendingApprovals || '0'}
          icon={Clock}
          color={stats?.pendingApprovals ? 'yellow' : 'green'}
        />
        <StatCard
          title="Integrity Issues"
          value={stats?.integrityIssues || '0'}
          icon={stats?.integrityIssues ? FileCheck : Shield}
          color={stats?.integrityIssues ? 'red' : 'green'}
        />
      </div>

      {/* Event Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
          <h2 className="text-lg font-semibold mb-4">Events by Type</h2>
          <div className="space-y-3">
            {stats?.byType && Object.entries(stats.byType).map(([type, count]) => (
              <div key={type} className="flex items-center justify-between">
                <span className="text-gray-400 text-sm">{type.replace(/_/g, ' ')}</span>
                <div className="flex items-center gap-2">
                  <div className="w-32 bg-gray-700 rounded-full h-2">
                    <div 
                      className="bg-claw-500 h-2 rounded-full"
                      style={{ width: `${Math.min((count / stats.totalEvents) * 100, 100)}%` }}
                    />
                  </div>
                  <span className="text-sm font-mono w-12 text-right">{count}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
          <h2 className="text-lg font-semibold mb-4">Events by Level</h2>
          <div className="grid grid-cols-2 gap-4">
            {stats?.byLevel && Object.entries(stats.byLevel).map(([level, count]) => (
              <div key={level} className="bg-gray-700/50 rounded-lg p-4">
                <div className={`text-2xl font-bold ${levelColors[level] || 'text-gray-400'}`}>
                  {count}
                </div>
                <div className="text-sm text-gray-400 capitalize">{level}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Recent Activity */}
      <div className="bg-gray-800 rounded-xl border border-gray-700">
        <div className="p-4 border-b border-gray-700">
          <h2 className="text-lg font-semibold">Recent Activity</h2>
        </div>
        <div className="divide-y divide-gray-700">
          {recentLogs.map((log, i) => (
            <div key={i} className="p-4 hover:bg-gray-700/50 transition-colors">
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                      log.level === 'critical' ? 'bg-red-500/20 text-red-400' :
                      log.level === 'error' ? 'bg-orange-500/20 text-orange-400' :
                      log.level === 'warn' ? 'bg-yellow-500/20 text-yellow-400' :
                      'bg-blue-500/20 text-blue-400'
                    }`}>
                      {log.level}
                    </span>
                    <span className="text-sm text-gray-400">{log.eventType}</span>
                  </div>
                  <p className="mt-1 text-sm truncate">{log.message}</p>
                </div>
                <span className="text-xs text-gray-500 whitespace-nowrap">
                  {new Date(log.timestamp).toLocaleTimeString()}
                </span>
              </div>
            </div>
          ))}
          {recentLogs.length === 0 && (
            <div className="p-8 text-center text-gray-500">
              No recent activity
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
