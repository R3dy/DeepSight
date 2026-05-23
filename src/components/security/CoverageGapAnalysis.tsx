import { useState } from 'react';
import type { CoverageGap, AttackCoverageData } from '../../types';

interface CoverageGapAnalysisProps {
  data: AttackCoverageData | null;
  isLoading: boolean;
}

const SEVERITY_COLORS: Record<string, string> = {
  'Reconnaissance': '#8b5cf6',
  'Initial Access': '#ef4444',
  'Execution': '#f97316',
  'Persistence': '#f59e0b',
  'Privilege Escalation': '#ec4899',
  'Defense Evasion': '#a855f7',
  'Credential Access': '#dc2626',
  'Discovery': '#3b82f6',
  'Lateral Movement': '#e11d48',
  'Collection': '#06b6d4',
  'Command and Control': '#ef4444',
  'Exfiltration': '#f97316',
  'Impact': '#dc2626',
};

function getTacticColor(tactic: string): string {
  return SEVERITY_COLORS[tactic] ?? '#6b7280';
}

function GapCard({ gap }: { gap: CoverageGap }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="rounded-lg border border-[#30363d] bg-[#0d1117] overflow-hidden">
      <button
        type="button"
        onClick={() => setExpanded(!expanded)}
        className="w-full text-left p-3 flex items-center gap-3 hover:bg-[#161b22]/50 transition-colors"
      >
        <span
          className="w-2 h-2 rounded-full flex-shrink-0"
          style={{ backgroundColor: getTacticColor(gap.tactic) }}
        />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs font-mono text-[#e1e4e8]">{gap.technique_id}</span>
            <span className="text-xs text-[#e1e4e8] truncate">{gap.technique_name}</span>
          </div>
          <span className="text-[9px] text-[#8b949e]">
            {gap.tactic} ({gap.tactic_id})
          </span>
        </div>
        <span className="text-[10px] text-[#8b949e]">
          {expanded ? '▲' : '▼'}
        </span>
      </button>

      {expanded && (
        <div className="px-3 pb-3 pt-0 border-t border-[#21262d]">
          <div className="mt-2 pt-2">
            <span className="text-[9px] uppercase tracking-wide text-[#6e7681] font-semibold">
              Recommendation
            </span>
            <p className="text-[11px] text-[#e1e4e8] mt-1 leading-relaxed">
              {gap.recommendation}
            </p>
          </div>
          <div className="mt-2 flex items-center gap-2">
            <span className="text-[9px] uppercase tracking-wide text-[#6e7681] font-semibold">
              Tags
            </span>
            <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-[#f59e0b]/10 text-[#f59e0b] border border-[#f59e0b]/20">
              {gap.tactic_id}
            </span>
            <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-[#ef4444]/10 text-[#ef4444] border border-[#ef4444]/20">
              Gap
            </span>
          </div>
        </div>
      )}
    </div>
  );
}

export function CoverageGapAnalysis({ data, isLoading }: CoverageGapAnalysisProps) {
  const [filterTactic, setFilterTactic] = useState<string | null>(null);

  if (isLoading) {
    return (
      <div className="space-y-2">
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className="rounded-lg border border-[#30363d] bg-[#0d1117] p-3 animate-pulse">
            <div className="h-4 w-48 bg-[#21262d] rounded mb-2" />
            <div className="h-3 w-32 bg-[#21262d] rounded" />
          </div>
        ))}
      </div>
    );
  }

  if (!data || !data.gaps || data.gaps.length === 0) {
    return (
      <div className="text-center py-8 text-[#8b949e]">
        <div className="text-xl mb-1">✅</div>
        <p className="text-xs">No coverage gaps — all techniques are covered</p>
      </div>
    );
  }

  // Get unique tactics for filter
  const tactics = Array.from(new Set(data.gaps.map((g: CoverageGap) => g.tactic))).sort();

  const filteredGaps = filterTactic
    ? data.gaps.filter((g: CoverageGap) => g.tactic === filterTactic)
    : data.gaps;

  return (
    <div className="space-y-3">
      {/* Summary */}
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div>
          <h4 className="text-sm font-semibold text-[#e1e4e8]">Coverage Gap Analysis</h4>
          <p className="text-[10px] text-[#8b949e]">
            {data.gaps.length} uncovered technique{data.gaps.length !== 1 ? 's' : ''} across{' '}
            {tactics.length} tactic{tactics.length !== 1 ? 's' : ''}
          </p>
        </div>
      </div>

      {/* Tactic Filter */}
      <div className="flex flex-wrap gap-1.5">
        <button
          type="button"
          onClick={() => setFilterTactic(null)}
          className={`px-2 py-0.5 rounded text-[10px] font-medium transition-colors border ${
            filterTactic === null
              ? 'bg-[#a78bfa]/15 text-[#a78bfa] border-[#a78bfa]/30'
              : 'text-[#8b949e] border-[#30363d] hover:border-[#a78bfa]/30'
          }`}
        >
          All ({data.gaps.length})
        </button>
        {tactics.map((tactic: string) => {
          const count = data.gaps.filter((g: CoverageGap) => g.tactic === tactic).length;
          return (
            <button
              key={tactic}
              type="button"
              onClick={() => setFilterTactic(tactic)}
              className={`px-2 py-0.5 rounded text-[10px] font-medium transition-colors border ${
                filterTactic === tactic
                  ? 'bg-[#a78bfa]/15 text-[#a78bfa] border-[#a78bfa]/30'
                  : 'text-[#8b949e] border-[#30363d] hover:border-[#a78bfa]/30'
              }`}
            >
              <span
                className="inline-block w-1.5 h-1.5 rounded-full mr-1"
                style={{ backgroundColor: getTacticColor(tactic) }}
              />
              {tactic} ({count})
            </button>
          );
        })}
      </div>

      {/* Gap List */}
      <div className="space-y-1.5 max-h-[500px] overflow-y-auto pr-1">
        {filteredGaps.map((gap: CoverageGap, i: number) => (
          <GapCard key={`${gap.technique_id}-${i}`} gap={gap} />
        ))}
      </div>

      {filteredGaps.length === 0 && (
        <div className="text-center py-4 text-[10px] text-[#8b949e]">
          No gaps for selected tactic
        </div>
      )}
    </div>
  );
}
