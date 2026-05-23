import { useState } from 'react';
import type { AttackCoverageData, AttackTacticCoverage, AttackTechnique } from '../../types';

interface AttackCoverageHeatmapProps {
  data: AttackCoverageData | null;
  isLoading: boolean;
}

function CoverageBar({ pct }: { pct: number }) {
  const color = pct >= 60 ? '#22c55e' : pct >= 30 ? '#f59e0b' : '#ef4444';
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-2 rounded-full bg-[#21262d] overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-500"
          style={{ width: `${Math.max(pct, 0.5)}%`, backgroundColor: color }}
        />
      </div>
      <span className="text-[10px] font-mono text-[#e1e4e8] w-10 text-right">{pct}%</span>
    </div>
  );
}

function TacticCard({
  tactic,
  onTechniqueClick,
}: {
  tactic: AttackTacticCoverage;
  onTechniqueClick: (tech: AttackTechnique, tacticName: string) => void;
}) {
  return (
    <div className="rounded-lg border border-[#30363d] bg-[#0d1117] p-3">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold text-[#e1e4e8]">{tactic.tactic}</span>
          <span className="text-[9px] text-[#6e7681] font-mono">{tactic.tactic_id}</span>
        </div>
        <span className="text-[10px] text-[#8b949e]">
          {tactic.covered_count}/{tactic.technique_count} covered
        </span>
      </div>
      <CoverageBar pct={tactic.coverage_pct} />
      <div className="mt-2 flex flex-wrap gap-1">
        {tactic.techniques.map((tech: AttackTechnique) => (
          <button
            key={tech.id}
            type="button"
            onClick={() => onTechniqueClick(tech, tactic.tactic)}
            title={`${tech.id}: ${tech.name}${tech.covered ? `\nRules: ${tech.rules.join(', ')}` : '\nNot covered'}`}
            className={`px-1.5 py-0.5 rounded text-[9px] font-mono transition-colors cursor-pointer border ${
              tech.covered
                ? 'bg-[#22c55e]/15 text-[#22c55e] border-[#22c55e]/30 hover:bg-[#22c55e]/25'
                : 'bg-[#ef4444]/10 text-[#ef4444]/70 border-[#ef4444]/15 hover:bg-[#ef4444]/20'
            }`}
          >
            {tech.id}
          </button>
        ))}
      </div>
    </div>
  );
}

function TechniqueDetail({
  technique,
  tacticName,
  onClose,
}: {
  technique: AttackTechnique;
  tacticName: string;
  onClose: () => void;
}) {
  return (
    <div className="rounded-lg border border-[#30363d] bg-[#161b22] p-4">
      <div className="flex items-center justify-between mb-3">
        <div>
          <h4 className="text-sm font-semibold text-[#e1e4e8]">
            {technique.id}: {technique.name}
          </h4>
          <p className="text-[10px] text-[#8b949e]">Tactic: {tacticName}</p>
        </div>
        <div className="flex items-center gap-2">
          <span
            className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
              technique.covered
                ? 'bg-[#22c55e]/15 text-[#22c55e]'
                : 'bg-[#ef4444]/15 text-[#ef4444]'
            }`}
          >
            {technique.covered ? '✓ Covered' : '✗ Uncovered'}
          </span>
          <button
            type="button"
            onClick={onClose}
            className="text-[#8b949e] hover:text-[#e1e4e8] text-sm"
          >
            ✕
          </button>
        </div>
      </div>

      {technique.covered && technique.rules.length > 0 ? (
        <div>
          <h5 className="text-[10px] font-semibold text-[#8b949e] mb-1 uppercase tracking-wide">
            Detection Rules
          </h5>
          <ul className="space-y-0.5">
            {technique.rules.map((rule: string, i: number) => (
              <li key={i} className="text-[11px] text-[#e1e4e8] flex items-center gap-1.5">
                <span className="w-1 h-1 rounded-full bg-[#a78bfa]" />
                {rule}
              </li>
            ))}
          </ul>
        </div>
      ) : (
        <div className="text-[11px] text-[#8b949e] italic">
          No detection rules currently cover this technique. Consider adding a Sigma rule
          or enabling a built-in detection rule to close this gap.
        </div>
      )}
    </div>
  );
}

export function AttackCoverageHeatmap({ data, isLoading }: AttackCoverageHeatmapProps) {
  const [selectedTechnique, setSelectedTechnique] = useState<AttackTechnique | null>(null);
  const [selectedTactic, setSelectedTactic] = useState<string>('');

  if (isLoading) {
    return (
      <div className="space-y-3">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="rounded-lg border border-[#30363d] bg-[#0d1117] p-4 animate-pulse">
            <div className="h-4 w-32 bg-[#21262d] rounded mb-3" />
            <div className="h-2 w-full bg-[#21262d] rounded mb-3" />
            <div className="flex flex-wrap gap-1">
              {Array.from({ length: 8 }).map((_, j) => (
                <div key={j} className="h-5 w-12 bg-[#21262d] rounded" />
              ))}
            </div>
          </div>
        ))}
      </div>
    );
  }

  if (!data || !data.tactics || data.tactics.length === 0) {
    return (
      <div className="text-center py-8 text-[#8b949e]">
        <div className="text-xl mb-1">🎯</div>
        <p className="text-xs">No ATT&amp;CK coverage data available</p>
      </div>
    );
  }

  const handleTechniqueClick = (technique: AttackTechnique, tacticName: string) => {
    setSelectedTechnique(technique);
    setSelectedTactic(tacticName);
  };

  return (
    <div className="space-y-4">
      {/* Overall Coverage Summary */}
      <div className="rounded-lg border border-[#30363d] bg-[#161b22] p-4">
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div>
            <h4 className="text-sm font-semibold text-[#e1e4e8]">ATT&amp;CK Coverage Summary</h4>
            <p className="text-[10px] text-[#8b949e]">
              {data.total_covered} of {data.total_techniques} techniques covered across {data.tactics.length} tactics
            </p>
          </div>
          <div className="flex items-center gap-3">
            <div className="text-center">
              <div
                className={`text-2xl font-bold font-mono ${
                  data.overall_coverage_pct >= 60
                    ? 'text-[#22c55e]'
                    : data.overall_coverage_pct >= 30
                      ? 'text-[#f59e0b]'
                      : 'text-[#ef4444]'
                }`}
              >
                {data.overall_coverage_pct}%
              </div>
              <div className="text-[9px] text-[#8b949e]">overall coverage</div>
            </div>
            <div className="w-px h-10 bg-[#30363d]" />
            <div className="flex gap-2 text-[10px]">
              <div className="flex items-center gap-1">
                <span className="w-3 h-3 rounded bg-[#22c55e]/30 border border-[#22c55e]/40" />
                <span className="text-[#8b949e]">Covered</span>
              </div>
              <div className="flex items-center gap-1">
                <span className="w-3 h-3 rounded bg-[#ef4444]/20 border border-[#ef4444]/30" />
                <span className="text-[#8b949e]">Uncovered</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Technique Detail Panel */}
      {selectedTechnique && (
        <TechniqueDetail
          technique={selectedTechnique}
          tacticName={selectedTactic}
          onClose={() => setSelectedTechnique(null)}
        />
      )}

      {/* Tactic Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {data.tactics.map((tactic: AttackTacticCoverage) => (
          <TacticCard
            key={tactic.tactic_id}
            tactic={tactic}
            onTechniqueClick={handleTechniqueClick}
          />
        ))}
      </div>
    </div>
  );
}
