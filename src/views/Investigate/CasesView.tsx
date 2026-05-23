import { useState } from 'react';
import { Routes, Route } from 'react-router-dom';
import { CaseList } from './CaseList';
import { CaseDetail } from './CaseDetail';
import { CreateCaseModal } from './CreateCaseModal';

export function CasesView() {
  const [createModalOpen, setCreateModalOpen] = useState(false);

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-xl font-bold text-[#e1e4e8]">Case Management</h2>
        <p className="text-sm text-[#8b949e]">Manage security incidents through their full lifecycle</p>
      </div>

      <Routes>
        <Route
          index
          element={<CaseList onCreateNew={() => setCreateModalOpen(true)} />}
        />
        <Route path=":id" element={<CaseDetail />} />
      </Routes>

      <CreateCaseModal
        open={createModalOpen}
        onClose={() => setCreateModalOpen(false)}
      />
    </div>
  );
}
