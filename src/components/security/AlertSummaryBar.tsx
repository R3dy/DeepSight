import type { SecuritySummary } from '../../types';

interface AlertSummaryBarProps {
  summary: SecuritySummary | null;
  isLoading: boolean;
}

const SEVERITY_CARDS = [
  { key: 'critical', label: 'Critical', icon: '🔴', color: 'border-[#dc2626] bg-[#dc2626]/10 text-[#dc2626]' },
  { key: 'high', label: 'High', icon: '🟠', color: 'border-[#ea580c] bg-[#ea580c]/10 text-[#ea580c]' },
  { key: 'medium', label: 'Medium', icon: '🟡', color: 'border-[#f59e0b] bg-[#f59e0b]/10 text-[#f59e0b]' },
  { key: 'low', label: 'Low', icon: '🔵', color: 'border-[#3b82f6] bg-[#3b82f6]/10 text-[#3b82f6]' },
] as const;

export function AlertSummaryBar({ summary, isLoading }: AlertSummaryBarProps) {
  if (isLoading) {
    return (
      <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
        {SEVERITY_CARDS.map(card => (
          <div key={card.key} className="rounded-lg border border-[#30363d] bg-[#161b22] p-3 animate-pulse">
            <div className="h-4 w-12 bg-[#21262d] rounded mb-1" />
            <div className="h-5 w-8 bg-[#21262d] rounded" />
          </div>
        ))}
      </div>
    );
  }

  const counts = summary ?? { critical: 0, high: 0, medium: 0, low: 0, beaconing_count: 0, auth_failures_1h: 0, file_events_1h: 0 };

  return (
    <div className="space-y-2">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
        {SEVERITY_CARDS.map(card => (
          <div key={card.key} className={`rounded-lg border p-3 ${card.color}`}>
            <div className="flex items-center gap-1.5">
              <span className="text-xs">{card.icon}</span>
              <span className="text-[10px] font-medium uppercase opacity-70">{card.label}</span>
            </div>
            <div className="text-2xl font-bold mt-1">
              {counts[card.key]}
            </div>
          </div>
        ))}
      </div>
      <div className="flex gap-4 text-[10px] text-[#8b949e]">
        <span>🔗 Beaconing: {counts.beaconing_count}</span>
        <span>🔐 Auth Failures (1h): {counts.auth_failures_1h}</span>
        <span>📁 File Events (1h): {counts.file_events_1h}</span>
      </div>
    </div>
  );
}
