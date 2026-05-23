import { Link } from 'react-router-dom';

export function NotFound() {
  return (
    <div className="flex items-center justify-center min-h-[60vh]">
      <div className="text-center">
        <div className="text-6xl mb-4">🔭</div>
        <h2 className="text-2xl font-bold text-[#e1e4e8] mb-2">404 — Page Not Found</h2>
        <p className="text-sm text-[#8b949e] mb-6">
          The page you're looking for doesn't exist or has moved.
        </p>
        <Link
          to="/dashboard"
          className="inline-block px-4 py-2 rounded-lg bg-[#a78bfa] text-white font-medium hover:bg-[#7c3aed] transition-colors"
        >
          Back to Dashboard
        </Link>
      </div>
    </div>
  );
}
