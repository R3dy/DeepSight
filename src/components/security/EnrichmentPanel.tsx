import { useState, useCallback } from 'react';
import { useQuery } from '@tanstack/react-query';
import { getPlaybookStatus, getPlaybooks, runPlaybook } from '../../api/playbooks';
import type {
  EnrichmentData,
  PlaybookResult,
  EnrichmentStepResult,
  PlaybookInfo,
  RunPlaybookRequest,
} from '../../api/playbooks';

interface EnrichmentPanelProps {
  alertId?: number;
  sourceIp?: string;
  sourceHost?: string;
  category?: string;
  severity?: string;
}

/** Color mapping for enrichment status badges */
function statusBadge(status: string) {
  const map: Record<string, { bg: string; text: string; label: string }> = {
    success: { bg: 'bg-[#238636]/15', text: 'text-[#3fb950]', label: '✓ Success' },
    partial: { bg: 'bg-[#d29922]/15', text: 'text-[#d29922]', label: '⚠ Partial' },
    error: { bg: 'bg-[#da3633]/15', text: 'text-[#f85149]', label: '✗ Error' },
    running: { bg: 'bg-[#a78bfa]/15', text: 'text-[#a78bfa]', label: '… Running' },
    pending: { bg: 'bg-[#8b949e]/15', text: 'text-[#8b949e]', label: '○ Pending' },
  };
  return map[status] || map.pending;
}

/** Expandable JSON tree — simple key-value render */
function JsonBlob({ data }: { data: Record<string, unknown> | null }) {
  if (!data || Object.keys(data).length === 0) {
    return <span className="text-[#484f58] italic">—</span>;
  }

  // Skip placeholder fields
  const skipped = new Set(['skipped', 'reason']);

  // Format IP reputation data
  const renderValue = (val: unknown): string => {
    if (val === null) return '—';
    if (typeof val === 'boolean') return val ? 'Yes' : 'No';
    if (typeof val === 'object') {
      return JSON.stringify(val, null, 0).slice(0, 120);
    }
    return String(val);
  };

  const entries = Object.entries(data).filter(([k]) => !skipped.has(k));
  if (entries.length === 0) return <span className="text-[#484f58] italic">—</span>;

  return (
    <div className="space-y-0.5">
      {entries.map(([key, val]) => {
        // Nested IP results
        if (key === 'ips' || key === 'indicators' || key === 'targets' || key === 'domains' || key === 'hashes' || key === 'dns' || key === 'results') {
          const obj = val as Record<string, unknown> | undefined;
          if (!obj) return null;

          return Object.entries(obj).map(([subKey, subVal]) => {
            const inner = subVal as Record<string, unknown> | undefined;
            if (!inner || typeof inner !== 'object') {
              return (
                <div key={`${key}-${subKey}`} className="flex gap-2 text-xs py-0.5">
                  <span className="text-[#a78bfa] font-mono shrink-0">{subKey}</span>
                  <span className="text-[#8b949e]">{renderValue(subVal)}</span>
                </div>
              );
            }

            // For nested objects like IP -> {country, isp, etc.}
            return (
              <div key={`${key}-${subKey}`} className="ml-2 border-l border-[#30363d] pl-2 py-1">
                <div className="text-xs text-[#a78bfa] font-mono mb-0.5">{subKey}</div>
                {Object.entries(inner).map(([ik, iv]) => {
                  if (ik === 'coordinates' || ik === 'pulses' || ik === 'urls' || ik === 'name_servers') {
                    return null; // skip large nested arrays in summary
                  }
                  return (
                    <div key={`${subKey}-${ik}`} className="flex gap-2 text-xs py-0.5">
                      <span className="text-[#8b949e] w-32 shrink-0 truncate">{ik}</span>
                      <span className="text-[#e1e4e8]">{renderValue(iv)}</span>
                    </div>
                  );
                })}
              </div>
            );
          });
        }

        return (
          <div key={key} className="flex gap-2 text-xs py-0.5">
            <span className="text-[#8b949e] w-32 shrink-0 truncate">{key}</span>
            <span className="text-[#e1e4e8]">{renderValue(val)}</span>
          </div>
        );
      })}
    </div>
  );
}

/** Step result row with expandable detail */
function StepRow({ step }: { step: EnrichmentStepResult }) {
  const [expanded, setExpanded] = useState(false);
  const st = statusBadge(step.status);

  const isSkipped = !!(step.data && typeof step.data === 'object' && (step.data as Record<string, unknown>).skipped);
  const skipReason = isSkipped ? (step.data as Record<string, unknown>).reason : null;

  return (
    <div className="border-t border-[#21262d] first:border-t-0">
      <button
        type="button"
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between px-3 py-2 hover:bg-[#1c2129] transition-colors text-left"
      >
        <div className="flex items-center gap-2">
          <span className={`text-[10px] px-1.5 py-0.5 rounded ${st.bg} ${st.text}`}>
            {st.label}
          </span>
          <span className="text-xs text-[#e1e4e8]">{step.name.replace(/_/g, ' ')}</span>
          {isSkipped && (
            <span className="text-[10px] text-[#8b949e]">({skipReason as string})</span>
          )}
        </div>
        <span className="text-[10px] text-[#484f58]">{step.duration_ms}ms</span>
      </button>
      {expanded && step.data && (
        <div className="px-3 pb-2 pl-8">
          <JsonBlob data={step.data} />
        </div>
      )}
      {expanded && step.error && (
        <div className="px-3 pb-2 pl-8">
          <p className="text-xs text-[#f85149]">{step.error}</p>
        </div>
      )}
    </div>
  );
}

/** Playbook result card */
function PlaybookCard({ result }: { result: PlaybookResult }) {
  const st = statusBadge(result.status);

  return (
    <div className="rounded border border-[#30363d] bg-[#0d1117] overflow-hidden">
      <div className="px-3 py-2 bg-[#161b22] border-b border-[#30363d] flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="text-xs font-medium text-[#e1e4e8]">
            {result.playbook.replace(/_/g, ' ')}
          </span>
          <span className={`text-[10px] px-1 rounded ${st.bg} ${st.text}`}>
            {st.label}
          </span>
        </div>
        {result.error && (
          <span className="text-[10px] text-[#f85149]" title={result.error}>
            {result.error.slice(0, 50)}
          </span>
        )}
      </div>
      <div>
        {result.steps.map((step, i) => (
          <StepRow key={`${step.name}-${i}`} step={step} />
        ))}
      </div>
    </div>
  );
}

/** Manual enrichment trigger */
function ManualTrigger({ alertId }: { alertId?: number }) {
  const [selectedPb, setSelectedPb] = useState('');
  const [manualIp, setManualIp] = useState('');
  const [running, setRunning] = useState(false);
  const [resultMsg, setResultMsg] = useState('');

  const { data: pbsResult } = useQuery({
    queryKey: ['playbooks'],
    queryFn: getPlaybooks,
    staleTime: 60000,
  });
  const playbooks: PlaybookInfo[] = pbsResult?.ok ? pbsResult.data.data : [];

  const handleRun = useCallback(async () => {
    if (!selectedPb) return;
    setRunning(true);
    setResultMsg('');

    const context: Record<string, unknown> = {};
    if (manualIp.trim()) {
      context.ips = [manualIp.trim()];
      context.source_ip = manualIp.trim();
    }

    const res = await runPlaybook({
      alert_id: alertId,
      playbook: selectedPb,
      context: context as RunPlaybookRequest['context'],
    });

    if (res.ok) {
      setResultMsg(`✓ ${res.data.data.playbook} completed: ${res.data.data.status}`);
    } else {
      setResultMsg(`✗ ${res.error || 'Unknown error'}`);
    }
    setRunning(false);
  }, [selectedPb, manualIp, alertId]);

  return (
    <div className="rounded border border-[#30363d] bg-[#0d1117] p-3">
      <h4 className="text-xs font-semibold text-[#e1e4e8] mb-2">⚡ Manual Enrichment</h4>
      <div className="flex flex-wrap items-center gap-2">
        <select
          value={selectedPb}
          onChange={e => setSelectedPb(e.target.value)}
          className="text-xs bg-[#161b22] border border-[#30363d] rounded px-2 py-1 text-[#e1e4e8]"
        >
          <option value="">Select playbook…</option>
          {playbooks.map(pb => (
            <option key={pb.name} value={pb.name}>{pb.name}</option>
          ))}
        </select>
        <input
          type="text"
          value={manualIp}
          onChange={e => setManualIp(e.target.value)}
          placeholder="IP or domain (optional)"
          className="text-xs bg-[#161b22] border border-[#30363d] rounded px-2 py-1 text-[#e1e4e8] w-40"
        />
        <button
          type="button"
          disabled={!selectedPb || running}
          onClick={handleRun}
          className="px-3 py-1 text-xs font-medium rounded bg-[#a78bfa]/15 text-[#a78bfa] border border-[#a78bfa]/30 hover:bg-[#a78bfa]/25 disabled:opacity-40 transition-colors"
        >
          {running ? 'Running…' : 'Run'}
        </button>
      </div>
      {resultMsg && (
        <p className={`text-xs mt-2 ${resultMsg.startsWith('✓') ? 'text-[#3fb950]' : 'text-[#f85149]'}`}>
          {resultMsg}
        </p>
      )}
    </div>
  );
}

/** Enrichment loading skeleton */
function EnrichmentSkeleton() {
  return (
    <div className="space-y-3 animate-pulse">
      {[1, 2].map(i => (
        <div key={i} className="rounded border border-[#30363d] bg-[#0d1117] p-3">
          <div className="h-4 w-40 bg-[#21262d] rounded mb-2" />
          <div className="h-3 w-64 bg-[#21262d] rounded mb-1" />
          <div className="h-3 w-48 bg-[#21262d] rounded" />
        </div>
      ))}
    </div>
  );
}

/** Main EnrichmentPanel */
export function EnrichmentPanel({ alertId, sourceIp, sourceHost, category, severity }: EnrichmentPanelProps) {
  const { data: statusResult, isLoading } = useQuery({
    queryKey: ['playbookStatus', alertId],
    queryFn: () => (alertId ? getPlaybookStatus(alertId) : null),
    enabled: !!alertId,
    staleTime: 10000,
    refetchInterval: 30000,
  });

  const enrichment: EnrichmentData | null = statusResult?.ok ? statusResult.data.data : null;

  return (
    <div className="space-y-3">
      {/* Alert context badge */}
      {(sourceIp || sourceHost || category) && (
        <div className="flex flex-wrap gap-1.5">
          {sourceIp && (
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#1c2129] text-[#a78bfa] font-mono">
              {sourceIp}
            </span>
          )}
          {sourceHost && (
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#1c2129] text-[#79c0ff]">
              {sourceHost}
            </span>
          )}
          {category && (
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#1c2129] text-[#8b949e]">
              {category}
            </span>
          )}
          {severity && (
            <span className={`text-[10px] px-1.5 py-0.5 rounded ${
              severity === 'critical' ? 'bg-[#da3633]/15 text-[#f85149]' :
              severity === 'high' ? 'bg-[#d29922]/15 text-[#d29922]' :
              'bg-[#1c2129] text-[#8b949e]'
            }`}>
              {severity}
            </span>
          )}
        </div>
      )}

      {/* Manual trigger */}
      <ManualTrigger alertId={alertId} />

      {/* Enrichment results */}
      {isLoading && <EnrichmentSkeleton />}

      {!isLoading && !enrichment && alertId && (
        <div className="text-xs text-[#8b949e] py-2">
          No enrichment data for this alert yet. Playbooks run automatically when alerts fire.
        </div>
      )}

      {enrichment && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-semibold text-[#e1e4e8]">🔬 Enrichment Results</h4>
            <span className="text-[10px] text-[#484f58]">
              {new Date(enrichment.enriched_at).toLocaleString()}
            </span>
          </div>

          {enrichment.playbook_results.length === 0 ? (
            <p className="text-xs text-[#8b949e]">No playbooks matched this alert.</p>
          ) : (
            enrichment.playbook_results.map((result, i) => (
              <PlaybookCard key={`${result.playbook}-${i}`} result={result} />
            ))
          )}
        </div>
      )}
    </div>
  );
}
