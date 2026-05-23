import { PieChart, Pie, Cell, ResponsiveContainer } from 'recharts';

interface GaugeChartProps {
  value: number;
  max?: number;
  size?: number;
  label?: string;
  colorThresholds?: {
    green: number;
    yellow: number;
    orange: number;
  };
}

const DEFAULT_THRESHOLDS = {
  green: 40,
  yellow: 60,
  orange: 80,
};

function gaugeColor(pct: number, thresholds = DEFAULT_THRESHOLDS): string {
  if (pct >= thresholds.orange) return '#ef4444'; // red
  if (pct >= thresholds.yellow) return '#f97316'; // orange
  if (pct >= thresholds.green) return '#f59e0b'; // yellow
  return '#22c55e'; // green
}

export function GaugeChart({
  value,
  max = 100,
  size = 140,
  label,
  colorThresholds,
}: GaugeChartProps) {
  const pct = Math.min(100, Math.max(0, (value / max) * 100));
  const color = gaugeColor(pct, colorThresholds);
  const remaining = 100 - pct;

  const data = [
    { name: 'Used', value: pct, fill: color },
    { name: 'Free', value: remaining, fill: '#21262d' },
  ];

  return (
    <div className="relative flex flex-col items-center" style={{ width: size, height: size }}>
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius="70%"
            outerRadius="90%"
            startAngle={180}
            endAngle={0}
            dataKey="value"
            strokeWidth={0}
            isAnimationActive={false}
          >
            {data.map((entry, i) => (
              <Cell key={i} fill={entry.fill} />
            ))}
          </Pie>
        </PieChart>
      </ResponsiveContainer>
      <div
        className="absolute flex flex-col items-center justify-center"
        style={{
          top: '55%',
          left: '50%',
          transform: 'translate(-50%, -50%)',
        }}
      >
        <span
          className="text-2xl font-bold leading-none"
          style={{ color }}
        >
          {pct.toFixed(0)}%
        </span>
        {label && (
          <span className="text-[10px] text-[#8b949e] mt-0.5">{label}</span>
        )}
      </div>
    </div>
  );
}
