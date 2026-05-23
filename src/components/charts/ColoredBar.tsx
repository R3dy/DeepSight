import { getColor } from './colors';

interface ColoredBarProps {
  value: number;
  max?: number;
  color?: string;
  showLabel?: boolean;
  className?: string;
}

export function ColoredBar({
  value,
  max = 100,
  color,
  showLabel = true,
  className = '',
}: ColoredBarProps) {
  const pct = Math.min(100, Math.max(0, (value / max) * 100));
  const barColor = color ?? getColor(0);

  return (
    <div className={`flex items-center gap-2 ${className}`}>
      <div className="flex-1 h-2 bg-[#21262d] rounded-full overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-300"
          style={{ width: `${pct}%`, backgroundColor: barColor }}
        />
      </div>
      {showLabel && (
        <span className="text-xs text-[#8b949e] font-mono w-12 text-right">
          {pct.toFixed(1)}%
        </span>
      )}
    </div>
  );
}
