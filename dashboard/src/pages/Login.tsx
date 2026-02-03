import { useState } from 'react';
import { Shield, Key, AlertCircle } from 'lucide-react';

interface LoginProps {
  onLogin: (apiKey: string) => void;
}

export default function Login({ onLogin }: LoginProps) {
  const [apiKey, setApiKey] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      // Verify API key
      const response = await fetch('/api/health', {
        headers: { 'Authorization': `Bearer ${apiKey}` },
      });

      if (response.ok) {
        onLogin(apiKey);
      } else {
        setError('Invalid API key');
      }
    } catch {
      setError('Could not connect to server');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-900 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-claw-500/20 mb-4">
            <Shield className="w-8 h-8 text-claw-400" />
          </div>
          <h1 className="text-2xl font-bold">ClawGuard Dashboard</h1>
          <p className="text-gray-400 mt-2">Enter your API key to continue</p>
        </div>

        <form onSubmit={handleSubmit} className="bg-gray-800 rounded-xl p-6 border border-gray-700">
          <div className="space-y-4">
            <div>
              <label htmlFor="apiKey" className="block text-sm font-medium text-gray-300 mb-2">
                API Key
              </label>
              <div className="relative">
                <Key className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
                <input
                  id="apiKey"
                  type="password"
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  placeholder="Enter your API key"
                  className="w-full pl-10 pr-4 py-2 bg-gray-700 border border-gray-600 rounded-lg 
                    text-white placeholder-gray-500 focus:outline-none focus:ring-2 
                    focus:ring-claw-500 focus:border-transparent"
                />
              </div>
            </div>

            {error && (
              <div className="flex items-center gap-2 text-red-400 text-sm">
                <AlertCircle className="w-4 h-4" />
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={!apiKey || loading}
              className="w-full py-2 px-4 bg-claw-500 hover:bg-claw-600 disabled:bg-gray-600 
                disabled:cursor-not-allowed rounded-lg font-medium transition-colors"
            >
              {loading ? 'Connecting...' : 'Connect'}
            </button>
          </div>

          <p className="mt-4 text-xs text-gray-500 text-center">
            Default dev key: <code className="bg-gray-700 px-1 rounded">clawguard-dev-key</code>
          </p>
        </form>
      </div>
    </div>
  );
}
