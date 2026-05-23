import type { CaseStatus } from '../../types';

const STATUS_CONFIG: Record<CaseStatus, { label: string; color: string }> = {
  new: { label: 'New', color: 'bg-blue-500/20 text-blue-300 border-blue-500/30' },
  investigating: { label: 'Investigating', color: 'bg-amber-500/20 text-amber-300 border-amber-500/30' },
  escalated: { label: 'Escalated', color: 'bg-rose-500/20 text-rose-300 border-rose-500/30' },
  resolved: { label: 'Resolved', color: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30' },
  closed: { label: 'Closed', color: 'bg-slate-500/20 text-slate-300 border-slate-500/30' },
};

interface CaseStatusBadgeProps {
  status: CaseStatus;
  className?: string;
}

export function CaseStatusBadge({ status, className = '' }: CaseStatusBadgeProps) {
  const config = STATUS_CONFIG[status] ?? STATUS_CONFIG.new;
  return (
    <span
      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium border ${config.color} ${className}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${config.color.split(' ')[0]}`} aria-hidden="true" />
      {config.label}
    </span>
  );
}

/** Return the valid status transitions from a given status. */
export function getValidTransitions(current: CaseStatus): CaseStatus[] {
  const transitions: Record<CaseStatus, CaseStatus[]> = {
    new: ['investigating', 'escalated', 'resolved', 'closed'],
    investigating: ['escalated', 'resolved', 'closed'],
    escalated: ['new', 'investigating', 'resolved', 'closed'],
    resolved: ['closed', 'investigating'],
    closed: ['investigating'],
  };
  return transitions[current] ?? [];
}
