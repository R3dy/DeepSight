import { useState, type FormEvent } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { createCase } from '../../api/cases';
import type { CaseSeverity, CasePriority } from '../../types';

interface CreateCaseModalProps {
  open: boolean;
  onClose: () => void;
}

export function CreateCaseModal({ open, onClose }: CreateCaseModalProps) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [severity, setSeverity] = useState<CaseSeverity>('medium');
  const [priority, setPriority] = useState<CasePriority>('medium');
  const [sourceHost, setSourceHost] = useState('');
  const [tagsStr, setTagsStr] = useState('');
  const [formError, setFormError] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: () =>
      createCase({
        title,
        description: description || undefined,
        severity,
        priority,
        source_host: sourceHost || undefined,
        tags: tagsStr
          ? tagsStr.split(',').map(t => t.trim()).filter(Boolean)
          : undefined,
      }),
    onSuccess: (result) => {
      if (result.ok && result.data) {
        queryClient.invalidateQueries({ queryKey: ['cases'] });
        onClose();
        // API v2 wraps response in {data: ...}, and apiClient returns the full JSON.
        // For create case: response = {data: caseObject}, so unwrap nested data.
        const caseData = result.data as unknown as { data?: { id: number }; id?: number };
        const caseId = caseData.data?.id ?? caseData.id;
        navigate(`/investigate/cases/${caseId}`);
      } else if (!result.ok) {
        setFormError(result.error || 'Failed to create case');
      }
    },
    onError: (err) => {
      setFormError(err instanceof Error ? err.message : 'Failed to create case. Please try again.');
    },
  });

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    setFormError(null);

    if (!title.trim()) {
      setFormError('Title is required');
      return;
    }

    mutation.mutate();
  };

  if (!open) return null;

  return (
    <>
      {/* Backdrop */}
      <div className="fixed inset-0 z-40 bg-black/60" onClick={onClose} aria-hidden="true" />

      {/* Modal */}
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-label="Create new case">
        <div className="w-full max-w-lg bg-[#161b22] border border-[#30363d] rounded-xl shadow-2xl" onClick={e => e.stopPropagation()}>
          <div className="p-6">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-lg font-semibold text-[#e1e4e8]">Create New Case</h2>
              <button
                type="button"
                onClick={onClose}
                className="text-[#8b949e] hover:text-[#e1e4e8] transition-colors text-xl leading-none"
                aria-label="Close"
              >
                ×
              </button>
            </div>

            {formError && (
              <div className="p-3 rounded-lg bg-[#f43f5e]/10 border border-[#f43f5e]/30 text-sm text-[#f43f5e] mb-4" role="alert">
                {formError}
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-4">
              {/* Title */}
              <div>
                <label htmlFor="case-title" className="block text-sm font-medium text-[#8b949e] mb-1">
                  Title <span className="text-[#f43f5e]">*</span>
                </label>
                <input
                  id="case-title"
                  type="text"
                  value={title}
                  onChange={e => setTitle(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-[#0f1117] border border-[#30363d] text-[#e1e4e8] placeholder-[#6e7681] focus:border-[#a78bfa] focus:ring-1 focus:ring-[#a78bfa] outline-none text-sm transition-colors"
                  placeholder="Enter case title"
                  autoFocus
                />
              </div>

              {/* Description */}
              <div>
                <label htmlFor="case-desc" className="block text-sm font-medium text-[#8b949e] mb-1">
                  Description
                </label>
                <textarea
                  id="case-desc"
                  value={description}
                  onChange={e => setDescription(e.target.value)}
                  rows={3}
                  className="w-full px-3 py-2 rounded-lg bg-[#0f1117] border border-[#30363d] text-[#e1e4e8] placeholder-[#6e7681] focus:border-[#a78bfa] focus:ring-1 focus:ring-[#a78bfa] outline-none text-sm resize-vertical transition-colors"
                  placeholder="Describe the incident..."
                />
              </div>

              {/* Severity + Priority */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label htmlFor="case-severity" className="block text-sm font-medium text-[#8b949e] mb-1">
                    Severity
                  </label>
                  <select
                    id="case-severity"
                    value={severity}
                    onChange={e => setSeverity(e.target.value as CaseSeverity)}
                    className="w-full px-3 py-2 rounded-lg bg-[#0f1117] border border-[#30363d] text-[#e1e4e8] text-sm focus:border-[#a78bfa] outline-none transition-colors"
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
                <div>
                  <label htmlFor="case-priority" className="block text-sm font-medium text-[#8b949e] mb-1">
                    Priority
                  </label>
                  <select
                    id="case-priority"
                    value={priority}
                    onChange={e => setPriority(e.target.value as CasePriority)}
                    className="w-full px-3 py-2 rounded-lg bg-[#0f1117] border border-[#30363d] text-[#e1e4e8] text-sm focus:border-[#a78bfa] outline-none transition-colors"
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
              </div>

              {/* Source host */}
              <div>
                <label htmlFor="case-host" className="block text-sm font-medium text-[#8b949e] mb-1">
                  Source Host
                </label>
                <input
                  id="case-host"
                  type="text"
                  value={sourceHost}
                  onChange={e => setSourceHost(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-[#0f1117] border border-[#30363d] text-[#e1e4e8] placeholder-[#6e7681] focus:border-[#a78bfa] focus:ring-1 focus:ring-[#a78bfa] outline-none text-sm transition-colors"
                  placeholder="e.g. web-server-01"
                />
              </div>

              {/* Tags */}
              <div>
                <label htmlFor="case-tags" className="block text-sm font-medium text-[#8b949e] mb-1">
                  Tags
                </label>
                <input
                  id="case-tags"
                  type="text"
                  value={tagsStr}
                  onChange={e => setTagsStr(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-[#0f1117] border border-[#30363d] text-[#e1e4e8] placeholder-[#6e7681] focus:border-[#a78bfa] focus:ring-1 focus:ring-[#a78bfa] outline-none text-sm transition-colors"
                  placeholder="e.g. phishing, ransomware (comma separated)"
                />
              </div>

              {/* Actions */}
              <div className="flex items-center justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={onClose}
                  className="px-4 py-2 rounded-lg bg-[#1c2129] border border-[#30363d] text-[#8b949e] text-sm hover:text-[#e1e4e8] transition-colors"
                  disabled={mutation.isPending}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={mutation.isPending}
                  className="px-4 py-2 rounded-lg bg-[#a78bfa] text-white text-sm font-medium hover:bg-[#7c3aed] disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  {mutation.isPending ? 'Creating...' : 'Create Case'}
                </button>
              </div>
            </form>
          </div>
        </div>
      </div>
    </>
  );
}
