import { Routes, Route, Navigate } from 'react-router-dom';
import { CasesView } from './Investigate/CasesView';

export function Investigate() {
  return (
    <Routes>
      <Route path="/" element={<Navigate to="cases" replace />} />
      <Route path="cases/*" element={<CasesView />} />
      <Route
        path="*"
        element={
          <div className="space-y-4">
            <div>
              <h2 className="text-xl font-bold text-[#e1e4e8]">Investigate</h2>
              <p className="text-sm text-[#8b949e]">Threat hunting, cases &amp; investigation timeline</p>
            </div>

            <div className="rounded-lg border border-dashed border-[#30363d] bg-[#161b22] p-8 text-center">
              <div className="text-4xl mb-3">🔍</div>
              <h3 className="text-lg font-medium text-[#e1e4e8] mb-2">Coming Soon</h3>
              <p className="text-sm text-[#8b949e] max-w-md mx-auto">
                Additional investigation tools are being built.
              </p>
            </div>
          </div>
        }
      />
    </Routes>
  );
}
