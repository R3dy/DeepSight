import { useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export function Login() {
  const { login, isLoading, error, clearError, isAuthenticated } = useAuth();
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  // Redirect if already authenticated
  if (isAuthenticated) {
    navigate('/dashboard', { replace: true });
    return null;
  }

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password.trim()) return;

    const success = await login({ username: username.trim(), password });
    if (success) {
      navigate('/dashboard', { replace: true });
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#0f1117] p-4">
      <div className="w-full max-w-sm">
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-[#a78bfa] tracking-tight mb-1">
            DeepSight
          </h1>
          <p className="text-sm text-[#8b949e]">Enterprise SIEM</p>
        </div>

        <form
          onSubmit={handleSubmit}
          className="bg-[#161b22] border border-[#30363d] rounded-xl p-6 space-y-4"
        >
          <h2 className="text-lg font-semibold text-[#e1e4e8]">Sign In</h2>

          {error && (
            <div className="p-3 rounded-lg bg-[#f43f5e]/10 border border-[#f43f5e]/30 text-sm text-[#f43f5e]">
              {error}
            </div>
          )}

          <div>
            <label htmlFor="username" className="block text-sm font-medium text-[#8b949e] mb-1">
              Username
            </label>
            <input
              id="username"
              type="text"
              value={username}
              onChange={e => {
                setUsername(e.target.value);
                if (error) clearError();
              }}
              className="w-full px-3 py-2 rounded-lg bg-[#0f1117] border border-[#30363d] text-[#e1e4e8] placeholder-[#6e7681] focus:border-[#a78bfa] focus:ring-1 focus:ring-[#a78bfa] outline-none transition-colors"
              placeholder="Enter username"
              autoComplete="username"
              autoFocus
            />
          </div>

          <div>
            <label htmlFor="password" className="block text-sm font-medium text-[#8b949e] mb-1">
              Password
            </label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={e => {
                setPassword(e.target.value);
                if (error) clearError();
              }}
              className="w-full px-3 py-2 rounded-lg bg-[#0f1117] border border-[#30363d] text-[#e1e4e8] placeholder-[#6e7681] focus:border-[#a78bfa] focus:ring-1 focus:ring-[#a78bfa] outline-none transition-colors"
              placeholder="Enter password"
              autoComplete="current-password"
            />
          </div>

          <button
            type="submit"
            disabled={isLoading || !username.trim() || !password.trim()}
            className="w-full py-2.5 px-4 rounded-lg bg-[#a78bfa] text-white font-medium hover:bg-[#7c3aed] disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {isLoading ? 'Signing in...' : 'Sign In'}
          </button>
        </form>

        <p className="text-center text-xs text-[#6e7681] mt-6">
          DeepSight Enterprise SIEM &copy; {new Date().getFullYear()}
        </p>
      </div>
    </div>
  );
}
