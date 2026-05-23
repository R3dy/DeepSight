import { ColoredBar } from '../charts/ColoredBar';
import type { BeaconingEvent } from '../../types';

interface BeaconingListProps {
  beaconing: BeaconingEvent[];
  isLoading: boolean;
}

function confidenceColor(conf: number): string {
  if (conf >= 70) return '#ef4444';
  if (conf >= 40) return '#f97316';
  return '#f59e0b';
}

export function BeaconingList({ beaconing, isLoading }: BeaconingListProps) {
  if (isLoading) {
    return (
      <div className="space-y-2">
        {Array.from({ length: 3 }).map((_, i) => (
          <div key={i} className="animate-pulse rounded border border-[#30363d] p-2">
            <div className="h-3 w-40 bg-[#21262d] rounded mb-1" />
            <div className="h-2 w-60 bg-[#21262d] rounded" />
          </div>
        ))}
      </div>
    );
  }

  if (beaconing.length === 0) {
    return (
      <div className="text-center py-4 text-[#8b949e]">
        <div className="text-xl mb-1">✅</div>
        <p className="text-xs">No beaconing detected</p>
      </div>
    );
  }

  return (
    <div className="space-y-2 max-h-[300px] overflow-y-auto">
      {beaconing.map((b, i) => (
        <div key={i} className="rounded border border-[#30363d] bg-[#0f1117] p-2 text-xs">
          <div className="flex items-center justify-between mb-1">
            <span className="font-medium text-[#e1e4e8]">
              {b.process_name} <span className="text-[#6e7681] font-mono">PID {b.pid}</span>
            </span>
            <span className="text-[10px] text-[#8b949e]">
              every {b.interval_seconds}s · {b.sample_count} samples
            </span>
          </div>
          <div className="text-[#8b949e] mb-1">
            → {b.remote_host}:{b.remote_port}
            {b.http_detail && (
              <span className="text-[#06b6d4] ml-2">{b.http_detail.substring(0, 60)}</span>
            )}
          </div>
          {b.user_agent && (
            <div className="text-[10px] text-[#6e7681] mb-1 truncate">
              UA: {b.user_agent.substring(0, 60)}
            </div>
          )}
          <div className="flex items-center gap-2">
            <span className="text-[10px] text-[#8b949e] w-16">Confidence</span>
            <ColoredBar
              value={b.confidence}
              color={confidenceColor(b.confidence)}
              showLabel={false}
              className="flex-1"
            />
            <span className="text-[10px] font-mono font-semibold" style={{ color: confidenceColor(b.confidence) }}>
              {b.confidence.toFixed(0)}%
            </span>
          </div>
        </div>
      ))}
    </div>
  );
}
