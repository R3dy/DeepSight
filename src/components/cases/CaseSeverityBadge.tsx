import type { CaseSeverity } from '../../types';

const SEVERITY_CONFIG: Record<CaseSeverity, { label: string; color: string }> = {
  critical: { label: 'Critical', color: 'bg-rose-500/20 text-rose-300 border-rose-500/30' },
  high: { label: 'High', color: 'bg-orange-500/20 text-orange-300 border-orange-500/30' },
  medium: { label: 'Medium', color: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30' },
  low: { label: 'Low', color: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30' },
};

interface CaseSeverityBadgeProps {
  severity: CaseSeverity;
  className?: string;
}

export function CaseSeverityBadge({ severity, className = '' }: CaseSeverityBadgeProps) {
  const config = SEVERITY_CONFIG[severity] ?? SEVERITY_CONFIG.medium;
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${config.color} ${className}`}
    >
      {config.label}
    </span>
  );
}
