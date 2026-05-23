type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

const SEVERITY_STYLES: Record<Severity, { bg: string; text: string; icon: string }> = {
  critical: { bg: 'bg-[#dc2626]/15', text: 'text-[#dc2626]', icon: '🔴' },
  high: { bg: 'bg-[#ea580c]/15', text: 'text-[#ea580c]', icon: '🟠' },
  medium: { bg: 'bg-[#f59e0b]/15', text: 'text-[#f59e0b]', icon: '🟡' },
  low: { bg: 'bg-[#3b82f6]/15', text: 'text-[#3b82f6]', icon: '🔵' },
  info: { bg: 'bg-[#6b7280]/15', text: 'text-[#6b7280]', icon: '⚪' },
};

interface SeverityBadgeProps {
  severity: Severity;
  size?: 'sm' | 'md';
}

export function SeverityBadge({ severity, size = 'md' }: SeverityBadgeProps) {
  const style = SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.info;
  const cls = size === 'sm'
    ? 'text-[10px] px-1.5 py-0.5'
    : 'text-xs px-2 py-0.5';

  return (
    <span
      className={`inline-flex items-center gap-1 font-medium rounded-full ${cls} ${style.bg} ${style.text}`}
    >
      <span className="text-[10px]">{style.icon}</span>
      {severity}
    </span>
  );
}
