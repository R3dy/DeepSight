import type { NetworkStats } from '../../types';

interface NetworkWidgetProps {
  network?: NetworkStats;
  isRemote: boolean;
  lastUpdated: string | null;
}

export function NetworkWidget({ network, isRemote, lastUpdated }: NetworkWidgetProps) {
  if (isRemote) {
    return (
      <div className="text-center py-4">
        <div className="text-2xl mb-2">🌐</div>
        <p className="text-xs text-[#8b949e]">
          Network data only available for collector host
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex gap-3 text-xs">
          <span className="text-[#22c55e]">
            {network?.tcp_established ?? '—'} est
          </span>
          <span className="text-[#06b6d4]">
            {network?.tcp_listen ?? '—'} listen
          </span>
          <span className="text-[#f59e0b]">
            {network?.udp_count ?? '—'} UDP
          </span>
        </div>
        <div className="flex gap-2 text-[10px] text-[#6e7681]">
          {network?.rx_mbps != null && <span>RX {network.rx_mbps.toFixed(1)} Mbps</span>}
          {network?.tx_mbps != null && <span>TX {network.tx_mbps.toFixed(1)} Mbps</span>}
        </div>
      </div>

      {/* TCP Listeners */}
      {network?.tcp_listeners && network.tcp_listeners.length > 0 && (
        <div className="max-h-[120px] overflow-y-auto">
          <table className="w-full text-[10px]">
            <thead>
              <tr className="text-[#6e7681] border-b border-[#21262d]">
                <th className="text-left py-1 font-medium">Port</th>
                <th className="text-left py-1 font-medium">Process</th>
                <th className="text-right py-1 font-medium">State</th>
              </tr>
            </thead>
            <tbody>
              {network.tcp_listeners.map((l, i) => (
                <tr key={i} className="border-b border-[#21262d]/50">
                  <td className="py-1 font-mono text-[#e1e4e8]">{l.port}</td>
                  <td className="py-1 text-[#8b949e] truncate max-w-[120px]">{l.process}</td>
                  <td className="py-1 text-right text-[#06b6d4]">{l.state}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Outbound HTTP */}
      {network?.outbound_http && network.outbound_http.length > 0 && (
        <div className="max-h-[80px] overflow-y-auto">
          <div className="text-[10px] text-[#6e7681] mb-1">Outbound HTTP</div>
          {network.outbound_http.slice(0, 5).map((conn, i) => (
            <div key={i} className="flex items-center gap-2 text-[10px] py-0.5">
              <span className="text-[#8b949e] font-mono">{conn.process}</span>
              <span className="text-[#06b6d4] truncate">{conn.url}</span>
              <span className="text-[#6e7681]">{conn.protocol}</span>
            </div>
          ))}
        </div>
      )}

      {lastUpdated && (
        <div className="text-[10px] text-[#6e7681] text-right">{lastUpdated}</div>
      )}
    </div>
  );
}
