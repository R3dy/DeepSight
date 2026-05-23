import { useQuery } from '@tanstack/react-query';
import { getProcessDetail } from '../../api';

interface ProcessDetailModalProps {
  pid: number;
  host?: string;
  onClose: () => void;
}

function KV({ label, value, color }: { label: string; value: string; color?: string }) {
  return (
    <div className="flex justify-between text-xs py-0.5">
      <span className="text-[#8b949e]">{label}</span>
      <span className="font-mono" style={{ color: color ?? '#e1e4e8' }}>{value}</span>
    </div>
  );
}

export function ProcessDetailModal({ pid, host, onClose }: ProcessDetailModalProps) {
  const { data: result, isLoading } = useQuery({
    queryKey: ['process', host, pid],
    queryFn: () => getProcessDetail(pid, host),
    staleTime: 3000,
  });

  const p = result?.ok ? result.data : null;

  // Close on Escape
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') onClose();
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      onClick={onClose}
      onKeyDown={handleKeyDown}
    >
      <div
        className="bg-[#161b22] border border-[#30363d] rounded-xl w-full max-w-3xl max-h-[85vh] overflow-y-auto shadow-2xl"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-[#30363d] sticky top-0 bg-[#161b22] z-10">
          <h3 className="text-lg font-bold text-[#e1e4e8]">
            🔍{' '}
            {p?.name ? (
              <>
                <span className="text-[#06b6d4]">{p.name}</span>
                <span className="text-[#8b949e] text-sm ml-2">
                  PID {p.pid} · {p.user} · {p.state}
                </span>
              </>
            ) : (
              'Process Detail'
            )}
          </h3>
          <button
            type="button"
            onClick={onClose}
            className="text-[#8b949e] hover:text-[#f43f5e] text-xl leading-none px-2"
          >
            ✕
          </button>
        </div>

        {/* Content */}
        <div className="p-4">
          {isLoading ? (
            <div className="text-center py-8 text-[#8b949e] animate-pulse">
              Loading process details...
            </div>
          ) : !p || p.error ? (
            <div className="text-center py-8 text-[#f43f5e]">
              {p?.error || 'Process not found'}
            </div>
          ) : (
            <div className="space-y-4">
              {/* Command line */}
              <div className="p-2 bg-[#0f1117] rounded-lg border border-[#30363d]">
                <code className="text-xs text-[#22c55e] break-all font-mono">
                  $ {p.cmdline ?? 'unknown'}
                </code>
              </div>

              {/* Grid sections */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Memory */}
                <div className="space-y-1">
                  <h4 className="text-xs font-semibold text-[#a78bfa] mb-2">💾 Memory</h4>
                  <KV label="RSS" value={`${p.vm_rss_mb ?? '?'} MB`} color="#a78bfa" />
                  <KV label="VSS" value={`${p.vm_size_mb ?? '?'} MB`} />
                  <KV label="Data" value={`${p.vm_data_mb ?? '?'} MB`} />
                  <KV label="Stack" value={`${p.vm_stk_mb ?? '?'} MB`} />
                  <KV label="Exe" value={`${p.vm_exe_mb ?? '?'} MB`} />
                  <KV label="Libs" value={`${p.vm_lib_mb ?? '?'} MB`} />
                  <KV
                    label="Swap"
                    value={`${p.vm_swap_mb ?? 0} MB`}
                    color={(p.vm_swap_mb ?? 0) > 0 ? '#ef4444' : undefined}
                  />
                </div>

                {/* Runtime */}
                <div className="space-y-1">
                  <h4 className="text-xs font-semibold text-[#06b6d4] mb-2">⚙️ Runtime</h4>
                  <KV label="Threads" value={`${p.threads ?? '?'}`} />
                  <KV label="CPU User" value={`${(p.cpu_user_s ?? 0).toFixed(1)}s`} />
                  <KV label="CPU System" value={`${(p.cpu_system_s ?? 0).toFixed(1)}s`} />
                  <KV label="CPU %" value={`${(p.cpu_percent ?? 0).toFixed(1)}%`} />
                  <KV label="Vol Ctx Sw" value={`${p.voluntary_ctxt_switches ?? 0}`} />
                  <KV label="Invol Ctx Sw" value={`${p.nonvoluntary_ctxt_switches ?? 0}`} />
                  <KV label="FDs Open" value={`${p.fd_count ?? 0}`} />
                </div>
              </div>

              {/* Network Connections */}
              <div className="space-y-1">
                <h4 className="text-xs font-semibold text-[#22c55e] mb-2">
                  🌐 Network Connections ({(p.network_connections ?? []).length})
                </h4>
                {p.network_connections && p.network_connections.length > 0 ? (
                  <div className="space-y-0.5 max-h-[120px] overflow-y-auto">
                    {p.network_connections.map((c, i) => (
                      <div key={i} className="text-xs font-mono p-1 bg-[#0f1117] rounded">
                        <span className="text-[#8b949e]">{c.proto}</span>{' '}
                        <span className="text-[#e1e4e8]">{c.local}</span>{' '}
                        <span className="text-[#6e7681]">→</span>{' '}
                        <span className="text-[#e1e4e8]">{c.remote}</span>{' '}
                        <span
                          className={
                            c.state === 'ESTABLISHED'
                              ? 'text-[#22c55e]'
                              : c.state === 'LISTEN'
                                ? 'text-[#06b6d4]'
                                : 'text-[#8b949e]'
                          }
                        >
                          {c.state}
                        </span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-xs text-[#6e7681]">none</div>
                )}
              </div>

              {/* Child processes */}
              <div className="space-y-1">
                <h4 className="text-xs font-semibold text-[#f59e0b] mb-2">
                  👶 Children ({p.child_count ?? 0})
                </h4>
                {p.child_details && p.child_details.length > 0 ? (
                  <div className="space-y-0.5">
                    {p.child_details.map((c, i) => (
                      <div key={i} className="text-xs p-1 bg-[#0f1117] rounded">
                        <span className="font-mono text-[#6e7681]">PID {c.pid}:</span>{' '}
                        <span className="text-[#e1e4e8]">{c.name}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-xs text-[#6e7681]">none</div>
                )}
              </div>

              {/* Open FDs */}
              <div className="space-y-1">
                <h4 className="text-xs font-semibold text-[#ec4899] mb-2">
                  📂 Open FDs ({p.fd_count ?? 0} total, sample)
                </h4>
                {p.fd_samples && p.fd_samples.length > 0 ? (
                  <div className="space-y-0.5 max-h-[150px] overflow-y-auto">
                    {p.fd_samples.map((f, i) => (
                      <div key={i} className="text-xs p-1 bg-[#0f1117] rounded font-mono">
                        <span className="text-[#6e7681]">{f.fd}:</span>{' '}
                        <span className="text-[#e1e4e8]">{f.target}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-xs text-[#6e7681]">none</div>
                )}
              </div>

              {/* Environment */}
              <div className="space-y-1">
                <h4 className="text-xs font-semibold text-[#8b949e] mb-2">🔧 Environment</h4>
                {p.environ && Object.keys(p.environ).length > 0 ? (
                  <div className="space-y-0.5 max-h-[150px] overflow-y-auto">
                    {Object.entries(p.environ).map(([k, v]) => (
                      <div key={k} className="text-xs p-1 bg-[#0f1117] rounded font-mono">
                        <span className="text-[#a78bfa]">{k}</span>
                        <span className="text-[#8b949e]">=</span>
                        <span className="text-[#e1e4e8]">{v}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-xs text-[#6e7681]">none</div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
