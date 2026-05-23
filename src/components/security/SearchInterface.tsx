import { useState, useCallback } from 'react';
import { useQuery } from '@tanstack/react-query';
import { searchEvents } from '../../api';
import { SeverityBadge } from '../charts/SeverityBadge';

const STORAGE_KEY = 'deepsight_search_history';

function getSearchHistory(): string[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch { return []; }
}

function saveSearchHistory(queries: string[]) {
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(queries.slice(0, 10))); } catch { /* ignore */ }
}

export function SearchInterface() {
  const [query, setQuery] = useState('');
  const [submittedQuery, setSubmittedQuery] = useState('');
  const [history, setHistory] = useState<string[]>(getSearchHistory);
  const [showHistory, setShowHistory] = useState(false);
  const [sortCol, setSortCol] = useState<string | null>(null);
  const [sortDir, setSortDir] = useState<1 | -1>(1);
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [expandedRow, setExpandedRow] = useState<number | null>(null);

  const { data: result, isLoading, isError } = useQuery({
    queryKey: ['search', submittedQuery],
    queryFn: () => searchEvents(submittedQuery),
    enabled: submittedQuery.length > 0,
    staleTime: 30000,
  });

  const searchData = result?.ok ? result.data : null;

  const handleSubmit = useCallback((q: string) => {
    if (!q.trim()) return;
    setSubmittedQuery(q.trim());
    setShowHistory(false);
    const updated = [q.trim(), ...history.filter(h => h !== q.trim())].slice(0, 10);
    setHistory(updated);
    saveSearchHistory(updated);
  }, [history]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') handleSubmit(query);
    if (e.key === 'Escape') setShowHistory(false);
  };

  // Type counts
  const results = searchData?.results ?? [];
  const typeCounts: Record<string, number> = {};
  results.forEach(r => {
    const t = r.type ?? 'unknown';
    typeCounts[t] = (typeCounts[t] ?? 0) + 1;
  });
  const types = ['all', ...Object.keys(typeCounts).sort()];

  // Filter by type
  const filtered = typeFilter === 'all'
    ? results
    : results.filter(r => r.type === typeFilter);

  // Sort
  const sorted = [...filtered].sort((a, b) => {
    if (!sortCol) return 0;
    const va = a[sortCol] ?? '';
    const vb = b[sortCol] ?? '';
    if (typeof va === 'string') return sortDir * String(va).localeCompare(String(vb));
    return sortDir * (Number(va) - Number(vb));
  });

  return (
    <div className="space-y-3">
      {/* Search input */}
      <div className="relative">
        <div className="flex gap-2">
          <div className="relative flex-1">
            <input
              type="text"
              value={query}
              onChange={e => setQuery(e.target.value)}
              onKeyDown={handleKeyDown}
              onFocus={() => setShowHistory(true)}
              placeholder="Search: category:intrusion severity:high host:server1 source:192.168 type:alert after:2026-05-20"
              className="w-full px-3 py-2 text-xs bg-[#0f1117] border border-[#30363d] rounded-lg text-[#e1e4e8] placeholder-[#6e7681] focus:border-[#a78bfa] outline-none font-mono"
            />
            {/* History dropdown */}
            {showHistory && history.length > 0 && (
              <div className="absolute top-full left-0 right-0 mt-1 bg-[#161b22] border border-[#30363d] rounded-lg shadow-xl z-50 overflow-hidden">
                <div className="flex items-center justify-between px-3 py-1.5 border-b border-[#30363d]">
                  <span className="text-[10px] text-[#8b949e]">Recent searches</span>
                  <button
                    type="button"
                    onClick={() => { setHistory([]); saveSearchHistory([]); }}
                    className="text-[10px] text-[#6e7681] hover:text-[#f43f5e]"
                  >
                    Clear all
                  </button>
                </div>
                {history.map((h, i) => (
                  <button
                    key={i}
                    type="button"
                    onClick={() => { setQuery(h); handleSubmit(h); }}
                    className="w-full px-3 py-1.5 text-xs text-left text-[#e1e4e8] hover:bg-[#1c2129] font-mono"
                  >
                    {h}
                  </button>
                ))}
              </div>
            )}
          </div>
          <button
            type="button"
            onClick={() => handleSubmit(query)}
            className="px-4 py-2 text-xs font-medium rounded-lg bg-[#a78bfa] text-white hover:bg-[#7c3aed] transition-colors"
          >
            Search
          </button>
        </div>
      </div>

      {/* Type filter tabs */}
      {results.length > 0 && types.length > 1 && (
        <div className="flex flex-wrap gap-1">
          {types.map(type => (
            <button
              key={type}
              type="button"
              onClick={() => setTypeFilter(type)}
              className={`px-2 py-0.5 text-[10px] font-medium rounded-full transition-colors ${
                typeFilter === type
                  ? 'bg-[#a78bfa]/20 text-[#a78bfa]'
                  : 'text-[#8b949e] hover:text-[#e1e4e8]'
              }`}
            >
              {type === 'all' ? 'All' : type}
              {type === 'all'
                ? ` (${results.length})`
                : ` (${typeCounts[type] ?? 0})`}
            </button>
          ))}
        </div>
      )}

      {/* Results */}
      {isLoading && (
        <div className="text-center py-4 text-[#8b949e] animate-pulse text-xs">
          Searching...
        </div>
      )}

      {isError && (
        <div className="text-center py-4">
          <div className="text-xl mb-1">⚠️</div>
          <p className="text-xs text-[#f43f5e]">Search failed</p>
        </div>
      )}

      {searchData && !isLoading && !isError && results.length === 0 && (
        <div className="text-center py-6 text-[#8b949e]">
          <div className="text-xl mb-1">📭</div>
          <p className="text-xs">No results</p>
        </div>
      )}

      {sorted.length > 0 && (
        <div className="overflow-hidden rounded-lg border border-[#30363d]">
          <div className="max-h-[400px] overflow-y-auto">
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-[#161b22]">
                <tr className="text-[#8b949e] border-b border-[#30363d]">
                  {[
                    { key: 'type', label: 'Type' },
                    { key: 'timestamp', label: 'Time' },
                    { key: 'severity', label: 'Severity' },
                    { key: 'host', label: 'Host' },
                    { key: 'title', label: 'Title' },
                  ].map(col => (
                    <th
                      key={col.key}
                      className="text-left py-1.5 px-2 font-medium cursor-pointer hover:text-[#a78bfa] select-none"
                      onClick={() => {
                        if (sortCol === col.key) setSortDir(d => d === 1 ? -1 : 1);
                        else { setSortCol(col.key); setSortDir(1); }
                      }}
                    >
                      {col.label}
                      {sortCol === col.key && (sortDir === 1 ? ' ▲' : ' ▼')}
                    </th>
                  ))}
                  <th className="py-1.5 px-2" />
                </tr>
              </thead>
              <tbody>
                {sorted.map((r, i) => (
                  <>
                    <tr
                      key={i}
                      className="border-b border-[#21262d]/50 hover:bg-[#1c2129] cursor-pointer"
                      onClick={() => setExpandedRow(expandedRow === i ? null : i)}
                    >
                      <td className="py-1.5 px-2 text-[#8b949e]">
                        {r.type === 'alert' ? '🚨' : r.type === 'auth' ? '🔐' : r.type === 'fim' ? '📁' : r.type === 'beaconing' ? '🔗' : r.type === 'dns' ? '🌐' : '📋'} {r.type}
                      </td>
                      <td className="py-1.5 px-2 text-[#6e7681] text-[10px] font-mono">{r.timestamp}</td>
                      <td className="py-1.5 px-2">
                        {r.severity ? <SeverityBadge severity={r.severity as 'critical' | 'high' | 'medium' | 'low' | 'info'} size="sm" /> : '—'}
                      </td>
                      <td className="py-1.5 px-2 text-[#e1e4e8] font-mono text-[10px]">{r.host ?? '—'}</td>
                      <td className="py-1.5 px-2 text-[#e1e4e8] truncate max-w-[200px]">
                        {r.title ?? String(r.description ?? '').substring(0, 60)}
                      </td>
                      <td className="py-1.5 px-2 text-[#6e7681] text-center">
                        {expandedRow === i ? '▼' : '▶'}
                      </td>
                    </tr>
                    {expandedRow === i && (
                      <tr key={`expanded-${i}`} className="bg-[#0f1117]">
                        <td colSpan={6} className="p-3">
                          <div className="grid grid-cols-2 gap-2 text-[10px]">
                            {Object.entries(r).map(([key, val]) => (
                              <div key={key} className="flex gap-2">
                                <span className="text-[#8b949e] font-medium">{key}:</span>
                                <span className="text-[#e1e4e8] break-all">
                                  {typeof val === 'object' ? JSON.stringify(val) : String(val)}
                                </span>
                              </div>
                            ))}
                          </div>
                        </td>
                      </tr>
                    )}
                  </>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
