import { useState, useEffect } from 'react';
import { 
  Lock, 
  FileText, 
  Clock, 
  Check, 
  X, 
  RefreshCw,
  AlertTriangle,
  ShieldCheck
} from 'lucide-react';
import { api } from '../api';

interface EnclaveProps {
  apiKey: string;
}

interface EnclaveFile {
  name: string;
  path: string;
  hash: string;
  lastModified: string;
  summary?: string;
}

interface ChangeRequest {
  id: string;
  file: string;
  diff: string;
  reason: string;
  requestedAt: string;
  requestedBy: string;
  status: 'pending' | 'approved' | 'denied' | 'expired';
}

interface IntegrityResult {
  tampered: string[];
  missing: string[];
}

export default function Enclave({ apiKey }: EnclaveProps) {
  const [files, setFiles] = useState<EnclaveFile[]>([]);
  const [pending, setPending] = useState<ChangeRequest[]>([]);
  const [integrity, setIntegrity] = useState<IntegrityResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [processing, setProcessing] = useState<string | null>(null);

  const loadData = async () => {
    setLoading(true);
    try {
      const [filesData, pendingData, integrityData] = await Promise.all([
        api.getEnclaveFiles(apiKey),
        api.getPendingRequests(apiKey),
        api.checkIntegrity(apiKey),
      ]);
      setFiles(filesData);
      setPending(pendingData);
      setIntegrity(integrityData);
    } catch (err) {
      console.error('Failed to load enclave data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [apiKey]);

  const handleApproval = async (requestId: string, approved: boolean) => {
    setProcessing(requestId);
    try {
      await api.approveRequest(apiKey, requestId, approved);
      await loadData();
    } catch (err) {
      console.error('Failed to process approval:', err);
    } finally {
      setProcessing(null);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 animate-spin text-claw-400" />
      </div>
    );
  }

  const hasIntegrityIssues = integrity && (integrity.tampered.length > 0 || integrity.missing.length > 0);

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Secure Enclave</h1>
          <p className="text-gray-400 mt-1">Protected files and pending approvals</p>
        </div>
        <button
          onClick={loadData}
          className="flex items-center gap-2 px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors"
        >
          <RefreshCw className="w-4 h-4" />
          Refresh
        </button>
      </div>

      {/* Integrity Status */}
      <div className={`p-4 rounded-xl border ${
        hasIntegrityIssues 
          ? 'bg-red-500/10 border-red-500/30' 
          : 'bg-green-500/10 border-green-500/30'
      }`}>
        <div className="flex items-center gap-3">
          {hasIntegrityIssues ? (
            <AlertTriangle className="w-6 h-6 text-red-400" />
          ) : (
            <ShieldCheck className="w-6 h-6 text-green-400" />
          )}
          <div>
            <h3 className={`font-medium ${hasIntegrityIssues ? 'text-red-400' : 'text-green-400'}`}>
              {hasIntegrityIssues ? 'Integrity Issues Detected' : 'All Files Intact'}
            </h3>
            {hasIntegrityIssues && (
              <p className="text-sm text-gray-400 mt-1">
                {integrity?.tampered.length ? `Tampered: ${integrity.tampered.join(', ')}` : ''}
                {integrity?.missing.length ? `Missing: ${integrity.missing.join(', ')}` : ''}
              </p>
            )}
          </div>
        </div>
      </div>

      {/* Pending Approvals */}
      {pending.length > 0 && (
        <div className="bg-gray-800 rounded-xl border border-gray-700">
          <div className="p-4 border-b border-gray-700 flex items-center gap-2">
            <Clock className="w-5 h-5 text-yellow-400" />
            <h2 className="text-lg font-semibold">Pending Approvals ({pending.length})</h2>
          </div>
          <div className="divide-y divide-gray-700">
            {pending.map((request) => (
              <div key={request.id} className="p-4">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <FileText className="w-4 h-4 text-gray-400" />
                      <span className="font-mono text-sm">{request.file}</span>
                    </div>
                    <p className="text-sm text-gray-400 mt-1">{request.reason}</p>
                    <p className="text-xs text-gray-500 mt-1">
                      Requested by {request.requestedBy} · {new Date(request.requestedAt).toLocaleString()}
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleApproval(request.id, false)}
                      disabled={processing === request.id}
                      className="p-2 bg-red-500/20 hover:bg-red-500/30 rounded-lg text-red-400 transition-colors"
                    >
                      <X className="w-5 h-5" />
                    </button>
                    <button
                      onClick={() => handleApproval(request.id, true)}
                      disabled={processing === request.id}
                      className="p-2 bg-green-500/20 hover:bg-green-500/30 rounded-lg text-green-400 transition-colors"
                    >
                      <Check className="w-5 h-5" />
                    </button>
                  </div>
                </div>

                {/* Diff Preview */}
                <details className="mt-3">
                  <summary className="text-sm text-claw-400 cursor-pointer hover:underline">
                    View diff
                  </summary>
                  <pre className="mt-2 p-3 bg-gray-900 rounded-lg text-xs overflow-x-auto">
                    {request.diff}
                  </pre>
                </details>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Protected Files */}
      <div className="bg-gray-800 rounded-xl border border-gray-700">
        <div className="p-4 border-b border-gray-700 flex items-center gap-2">
          <Lock className="w-5 h-5 text-claw-400" />
          <h2 className="text-lg font-semibold">Protected Files ({files.length})</h2>
        </div>
        <div className="divide-y divide-gray-700">
          {files.map((file) => (
            <div key={file.path} className="p-4 hover:bg-gray-700/50 transition-colors">
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <FileText className="w-4 h-4 text-gray-400" />
                    <span className="font-mono text-sm">{file.name}</span>
                  </div>
                  {file.summary && (
                    <p className="text-sm text-gray-400 mt-1">{file.summary}</p>
                  )}
                  <div className="flex items-center gap-4 mt-2 text-xs text-gray-500">
                    <span>Path: {file.path}</span>
                    <span>Modified: {new Date(file.lastModified).toLocaleDateString()}</span>
                  </div>
                </div>
                <div className="text-xs font-mono text-gray-500 bg-gray-700 px-2 py-1 rounded">
                  {file.hash.slice(0, 8)}...
                </div>
              </div>
            </div>
          ))}
          {files.length === 0 && (
            <div className="p-8 text-center text-gray-500">
              No protected files found
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
