import { useState, useCallback, useRef, type FormEvent } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useQuery, useQueryClient, useMutation } from '@tanstack/react-query';
import {
  getCase,
  updateCase,
  addCaseNote,
} from '../../api/cases';
import { CaseStatusBadge, getValidTransitions } from '../../components/cases/CaseStatusBadge';
import { CaseSeverityBadge } from '../../components/cases/CaseSeverityBadge';
import { useWebSocket } from '../../context/WebSocketContext';
import type { CaseIncident, CaseStatus } from '../../types';

function formatTimestamp(iso: string): string {
  // Handle both ISO format and "YYYY-MM-DD HH:MM:SS" format
  const normalized = iso.includes('T') ? iso : iso.replace(' ', 'T') + 'Z';
  const date = new Date(normalized);
  if (isNaN(date.getTime())) return iso;
  return date.toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function formatRelativeTime(iso: string): string {
  const normalized = iso.includes('T') ? iso : iso.replace(' ', 'T') + 'Z';
  const date = new Date(normalized);
  if (isNaN(date.getTime())) return iso;
  const diff = Date.now() - date.getTime();
  const seconds = Math.floor(diff / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  return date.toLocaleDateString();
}

interface StatusDropdownProps {
  currentStatus: CaseStatus;
  onStatusChange: (newStatus: CaseStatus) => void;
  disabled?: boolean;
}

function StatusDropdown({ currentStatus, onStatusChange, disabled }: StatusDropdownProps) {
  const [open, setOpen] = useState(false);
  const transitions = getValidTransitions(currentStatus);

  if (transitions.length === 0) return <CaseStatusBadge status={currentStatus} />;

  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        disabled={disabled}
        className="disabled:opacity-50"
        aria-label="Change status"
      >
        <CaseStatusBadge status={currentStatus} className="cursor-pointer hover:opacity-80 transition-opacity" />
        <span className="ml-1 text-[#8b949e] text-xs">▾</span>
      </button>
      {open && (
        <>
          <div className="fixed inset-0 z-10" onClick={() => setOpen(false)} aria-hidden="true" />
          <div className="absolute z-20 mt-1 w-44 rounded-lg bg-[#161b22] border border-[#30363d] shadow-xl py-1">
            {transitions.map(status => (
              <button
                key={status}
                type="button"
                className="w-full text-left px-3 py-2 text-sm text-[#e1e4e8] hover:bg-[#1c2129] transition-colors flex items-center gap-2"
                onClick={() => {
                  onStatusChange(status);
                  setOpen(false);
                }}
              >
                <CaseStatusBadge status={status} />
              </button>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

export function CaseDetail() {
  const { id } = useParams<{ id: string }>();
  const queryClient = useQueryClient();
  const { socket } = useWebSocket();
  const [newNote, setNewNote] = useState('');
  const [noteError, setNoteError] = useState<string | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);
  const noteInputRef = useRef<HTMLTextAreaElement>(null);

  const caseId = id ? parseInt(id, 10) : 0;

  const {
    data: caseResponse,
    isLoading,
    isError,
    error,
    refetch,
  } = useQuery({
    queryKey: ['case', caseId],
    queryFn: () => getCase(caseId),
    enabled: caseId > 0,
    refetchInterval: 15000,
  });

  // API v2 wraps responses in {data: ...}, and apiClient returns the full JSON body.
  // For single case: response = {data: caseObject}, so we need response.data
  const caseData = caseResponse?.ok ? caseResponse.data : null;
  const caseIncident = caseData && typeof caseData === 'object' && 'data' in caseData
    ? (caseData as { data: CaseIncident }).data
    : (caseData as CaseIncident | null);

  // WebSocket listener for live updates
  useCallback(() => {
    if (!socket) return;
    const handler = (data: { case_id?: number }) => {
      if (data?.case_id === caseId) {
        queryClient.invalidateQueries({ queryKey: ['case', caseId] });
        queryClient.invalidateQueries({ queryKey: ['cases'] });
      }
    };
    socket.on('incident_update', handler);
    return () => {
      socket.off('incident_update', handler);
    };
  }, [socket, caseId, queryClient])();

  // Status change mutation
  const statusMutation = useMutation({
    mutationFn: (newStatus: CaseStatus) =>
      updateCase(caseId, { status: newStatus }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['case', caseId] });
      queryClient.invalidateQueries({ queryKey: ['cases'] });
    },
    onError: () => {
      setStatusError('Failed to update status. Please try again.');
      setTimeout(() => setStatusError(null), 5000);
    },
  });

  // Add note mutation
  const noteMutation = useMutation({
    mutationFn: (content: string) => addCaseNote(caseId, content),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['case', caseId] });
    },
    onError: () => {
      setNoteError('Failed to add note. Please try again.');
    },
  });

  const handleNoteSubmit = (e: FormEvent) => {
    e.preventDefault();
    setNoteError(null);

    if (!newNote.trim()) {
      setNoteError('Note cannot be empty');
      return;
    }

    noteMutation.mutate(newNote.trim());
    setNewNote('');
  };

  const handleStatusChange = (newStatus: CaseStatus) => {
    setStatusError(null);
    statusMutation.mutate(newStatus);
  };

  // Loading state
  if (isLoading) {
    return (
      <div className="space-y-4 animate-pulse">
        <div className="h-8 bg-[#1c2129] rounded w-48" />
        <div className="h-6 bg-[#1c2129] rounded w-96" />
        <div className="h-64 bg-[#1c2129] rounded" />
      </div>
    );
  }

  // Error state
  if (isError) {
    return (
      <div className="rounded-lg border border-[#f43f5e]/30 bg-[#f43f5e]/5 p-8 text-center">
        <p className="text-[#f43f5e] text-sm mb-3">
          {error instanceof Error ? error.message : 'Failed to load case'}
        </p>
        <div className="flex items-center justify-center gap-3">
          <button
            type="button"
            onClick={() => refetch()}
            className="px-4 py-2 rounded-lg bg-[#f43f5e]/10 border border-[#f43f5e]/30 text-[#f43f5e] text-sm hover:bg-[#f43f5e]/20 transition-colors"
          >
            Retry
          </button>
          <Link
            to="/investigate/cases"
            className="px-4 py-2 rounded-lg bg-[#1c2129] border border-[#30363d] text-[#8b949e] text-sm hover:text-[#e1e4e8] transition-colors"
          >
            Back to Cases
          </Link>
        </div>
      </div>
    );
  }

  // Not found
  if (!caseIncident) {
    return (
      <div className="rounded-lg border border-dashed border-[#30363d] bg-[#161b22] p-12 text-center">
        <div className="text-4xl mb-4">🔍</div>
        <h3 className="text-lg font-medium text-[#e1e4e8] mb-2">Case not found</h3>
        <p className="text-sm text-[#8b949e] mb-4">
          The case you are looking for does not exist or has been deleted.
        </p>
        <Link
          to="/investigate/cases"
          className="px-4 py-2 rounded-lg bg-[#a78bfa] text-white text-sm font-medium hover:bg-[#7c3aed] transition-colors inline-block"
        >
          Back to Cases
        </Link>
      </div>
    );
  }

  const alerts = caseIncident.alerts ?? [];
  const notes = caseIncident.notes ?? [];

  return (
    <div className="space-y-6">
      {/* Breadcrumb */}
      <nav className="flex items-center gap-2 text-sm text-[#8b949e]" aria-label="Breadcrumb">
        <Link to="/investigate/cases" className="hover:text-[#e1e4e8] transition-colors">
          Cases
        </Link>
        <span>›</span>
        <span className="text-[#e1e4e8]">#{caseIncident.id}</span>
      </nav>

      {/* Error toasts */}
      {statusError && (
        <div className="p-3 rounded-lg bg-[#f43f5e]/10 border border-[#f43f5e]/30 text-sm text-[#f43f5e]" role="alert">
          {statusError}
        </div>
      )}

      {/* Header */}
      <div className="rounded-lg border border-[#30363d] bg-[#161b22] p-6">
        <div className="flex flex-col lg:flex-row lg:items-start lg:justify-between gap-4">
          <div className="space-y-3 min-w-0">
            <div className="flex items-center gap-3 flex-wrap">
              <span className="text-[#8b949e] font-mono text-sm">#{caseIncident.id}</span>
              <CaseSeverityBadge severity={caseIncident.severity} />
              <StatusDropdown
                currentStatus={caseIncident.status}
                onStatusChange={handleStatusChange}
                disabled={statusMutation.isPending}
              />
              {caseIncident.priority !== caseIncident.severity && (
                <span className="text-xs text-[#8b949e]">
                  Priority: <span className="capitalize text-[#e1e4e8]">{caseIncident.priority}</span>
                </span>
              )}
            </div>
            <h2 className="text-xl font-bold text-[#e1e4e8] break-words">{caseIncident.title}</h2>
            {caseIncident.description && (
              <p className="text-sm text-[#8b949e]">{caseIncident.description}</p>
            )}
            <div className="flex flex-wrap items-center gap-4 text-xs text-[#8b949e]">
              <span>Created: {formatTimestamp(caseIncident.created_at)}</span>
              <span>Updated: {formatRelativeTime(caseIncident.updated_at)}</span>
              {caseIncident.resolved_at && (
                <span>Resolved: {formatTimestamp(caseIncident.resolved_at)}</span>
              )}
              <span>Alerts: <span className="text-[#e1e4e8]">{caseIncident.alert_count}</span></span>
              {caseIncident.source_host && (
                <span>Host: <span className="text-[#e1e4e8]">{caseIncident.source_host}</span></span>
              )}
              {caseIncident.mitre_technique && (
                <span className="px-2 py-0.5 rounded bg-[#a78bfa]/10 text-[#a78bfa] font-mono">
                  {caseIncident.mitre_technique}
                </span>
              )}
            </div>
            {(caseIncident.tags ?? []).length > 0 && (
              <div className="flex flex-wrap gap-1">
                {caseIncident.tags.map(tag => (
                  <span key={tag} className="px-2 py-0.5 rounded-full bg-[#1c2129] text-[#8b949e] text-xs border border-[#30363d]">
                    {tag}
                  </span>
                ))}
              </div>
            )}
            {/* SLA timer */}
            {caseIncident.sla_deadline && caseIncident.status !== 'resolved' && caseIncident.status !== 'closed' && (
              <div className={`text-xs ${caseIncident.sla_breached ? 'text-[#f43f5e]' : 'text-[#d4a72c]'}`}>
                {caseIncident.sla_breached
                  ? '⚠️ SLA breached'
                  : `⏱ SLA: ${Math.ceil(caseIncident.sla_remaining_seconds / 3600)}h ${Math.ceil((caseIncident.sla_remaining_seconds % 3600) / 60)}m remaining`}
              </div>
            )}
          </div>

          {/* Assignee */}
          <div className="flex-shrink-0">
            <div className="flex items-center gap-2">
              <span className="text-xs text-[#8b949e]">Assignee:</span>
              <span className="text-sm text-[#e1e4e8]">
                {caseIncident.assignee_id ? `#${caseIncident.assignee_id}` : 'Unassigned'}
              </span>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left column: Timeline + Alerts */}
        <div className="lg:col-span-2 space-y-6">
          {/* Correlated Alerts */}
          <div className="rounded-lg border border-[#30363d] bg-[#161b22] p-6">
            <h3 className="text-lg font-semibold text-[#e1e4e8] mb-4">Correlated Alerts</h3>
            {alerts.length === 0 ? (
              <p className="text-sm text-[#8b949e] italic">No alerts linked to this case.</p>
            ) : (
              <div className="space-y-2">
                {alerts.map(alert => (
                  <div
                    key={alert.id}
                    className="flex items-start gap-3 p-3 rounded-lg bg-[#0f1117] border border-[#30363d] hover:border-[#a78bfa]/30 transition-colors"
                  >
                    <CaseSeverityBadge severity={alert.severity as 'critical' | 'high' | 'medium' | 'low'} />
                    <div className="min-w-0 flex-1">
                      <p className="text-sm text-[#e1e4e8] font-medium truncate">{alert.title}</p>
                      <p className="text-xs text-[#8b949e] mt-1">{alert.description}</p>
                      <div className="flex items-center gap-3 mt-1.5 text-xs text-[#6e7681]">
                        <span>{formatRelativeTime(alert.timestamp)}</span>
                        {alert.source_ip && <span>{alert.source_ip}</span>}
                        {alert.source_host && <span>{alert.source_host}</span>}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Activity Timeline */}
          <div className="rounded-lg border border-[#30363d] bg-[#161b22] p-6">
            <h3 className="text-lg font-semibold text-[#e1e4e8] mb-4">Activity Timeline</h3>
            <div className="space-y-3">
              <div className="flex gap-3">
                <div className="flex-shrink-0 w-2 h-2 mt-2 rounded-full bg-[#a78bfa]" />
                <div>
                  <p className="text-sm text-[#e1e4e8]">Case created</p>
                  <p className="text-xs text-[#8b949e]">{formatRelativeTime(caseIncident.created_at)}</p>
                </div>
              </div>
              {caseIncident.status !== 'new' && (
                <div className="flex gap-3">
                  <div className="flex-shrink-0 w-2 h-2 mt-2 rounded-full bg-[#d4a72c]" />
                  <div>
                    <p className="text-sm text-[#e1e4e8]">Status: {caseIncident.status}</p>
                    <p className="text-xs text-[#8b949e]">{formatRelativeTime(caseIncident.updated_at)}</p>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Resolution section (for resolved/closed cases) */}
          {(caseIncident.status === 'resolved' || caseIncident.status === 'closed') && (
            <div className="rounded-lg border border-[#30363d] bg-[#161b22] p-6">
              <h3 className="text-lg font-semibold text-[#e1e4e8] mb-4">Resolution</h3>
              {caseIncident.resolution ? (
                <div className="space-y-3">
                  <div>
                    <p className="text-xs text-[#8b949e] mb-1">Summary</p>
                    <p className="text-sm text-[#e1e4e8] whitespace-pre-wrap">{caseIncident.resolution}</p>
                  </div>
                  {caseIncident.resolved_note && (
                    <div>
                      <p className="text-xs text-[#8b949e] mb-1">Resolution Note</p>
                      <p className="text-sm text-[#e1e4e8] whitespace-pre-wrap">{caseIncident.resolved_note}</p>
                    </div>
                  )}
                </div>
              ) : (
                <p className="text-sm text-[#8b949e] italic">No resolution details documented.</p>
              )}
            </div>
          )}
        </div>

        {/* Right column: Notes */}
        <div className="space-y-6">
          <div className="rounded-lg border border-[#30363d] bg-[#161b22] p-6">
            <h3 className="text-lg font-semibold text-[#e1e4e8] mb-4">Notes</h3>

            {/* Add note form */}
            {caseIncident.status !== 'closed' && (
              <form onSubmit={handleNoteSubmit} className="mb-4">
                <textarea
                  ref={noteInputRef}
                  value={newNote}
                  onChange={e => {
                    setNewNote(e.target.value);
                    if (noteError) setNoteError(null);
                  }}
                  placeholder="Add a note... (supports markdown)"
                  rows={3}
                  className="w-full px-3 py-2 rounded-lg bg-[#0f1117] border border-[#30363d] text-[#e1e4e8] placeholder-[#6e7681] focus:border-[#a78bfa] focus:ring-1 focus:ring-[#a78bfa] outline-none text-sm resize-vertical transition-colors"
                  disabled={noteMutation.isPending}
                />
                {noteError && (
                  <p className="text-xs text-[#f43f5e] mt-1">{noteError}</p>
                )}
                <div className="flex items-center justify-between mt-2">
                  <span className="text-xs text-[#6e7681]">Ctrl+Enter to submit</span>
                  <button
                    type="submit"
                    disabled={noteMutation.isPending || !newNote.trim()}
                    className="px-4 py-1.5 rounded-lg bg-[#a78bfa] text-white text-sm font-medium hover:bg-[#7c3aed] disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                  >
                    {noteMutation.isPending ? 'Adding...' : 'Add Note'}
                  </button>
                </div>
              </form>
            )}

            {/* Notes list */}
            {notes.length === 0 ? (
              <p className="text-sm text-[#8b949e] italic text-center py-4">
                No notes yet. Add the first note above.
              </p>
            ) : (
              <div className="space-y-3 max-h-96 overflow-y-auto">
                {notes.map(note => (
                  <div
                    key={note.id}
                    className="p-3 rounded-lg bg-[#0f1117] border border-[#30363d]"
                  >
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="text-xs font-medium text-[#e1e4e8]">
                        {note.username || 'Unknown'}
                      </span>
                      <span className="text-xs text-[#6e7681]">
                        {formatRelativeTime(note.created_at)}
                      </span>
                    </div>
                    <p className="text-sm text-[#c9d1d9] whitespace-pre-wrap break-words">
                      {note.content}
                    </p>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
