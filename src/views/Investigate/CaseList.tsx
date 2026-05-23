import { useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  getPaginationRowModel,
  type SortingState,
  type ColumnDef,
  type PaginationState,
  flexRender,
} from '@tanstack/react-table';
import { getCases } from '../../api/cases';
import { CaseStatusBadge } from '../../components/cases/CaseStatusBadge';
import { CaseSeverityBadge } from '../../components/cases/CaseSeverityBadge';
import { useWebSocket } from '../../context/WebSocketContext';
import type { CaseIncident, CaseSeverity, CaseStatus, CaseSortField } from '../../types';

const PAGE_SIZE = 25;

const SEVERITY_OPTIONS: { label: string; value: CaseSeverity }[] = [
  { label: 'Critical', value: 'critical' },
  { label: 'High', value: 'high' },
  { label: 'Medium', value: 'medium' },
  { label: 'Low', value: 'low' },
];

const STATUS_OPTIONS: { label: string; value: CaseStatus }[] = [
  { label: 'New', value: 'new' },
  { label: 'Investigating', value: 'investigating' },
  { label: 'Escalated', value: 'escalated' },
  { label: 'Resolved', value: 'resolved' },
  { label: 'Closed', value: 'closed' },
];

function formatRelativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const seconds = Math.floor(diff / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  return new Date(iso).toLocaleDateString();
}

const columns: ColumnDef<CaseIncident>[] = [
  {
    id: 'id',
    header: 'ID',
    accessorKey: 'id',
    size: 70,
    cell: info => <span className="text-[#8b949e] font-mono text-xs">#{info.getValue<number>()}</span>,
  },
  {
    id: 'title',
    header: 'Title',
    accessorKey: 'title',
    cell: info => (
      <span className="text-[#e1e4e8] font-medium truncate max-w-[300px] block" title={info.getValue<string>()}>
        {info.getValue<string>()}
      </span>
    ),
  },
  {
    id: 'severity',
    header: 'Severity',
    accessorKey: 'severity',
    size: 100,
    cell: info => <CaseSeverityBadge severity={info.getValue<CaseSeverity>()} />,
  },
  {
    id: 'status',
    header: 'Status',
    accessorKey: 'status',
    size: 130,
    cell: info => <CaseStatusBadge status={info.getValue<CaseStatus>()} />,
  },
  {
    id: 'assignee_id',
    header: 'Assignee',
    accessorKey: 'assignee_id',
    size: 100,
    cell: info => {
      const val = info.getValue<number | null>();
      return (
        <span className={val ? 'text-[#e1e4e8] text-sm' : 'text-[#6e7681] text-sm italic'}>
          {val ? `#${val}` : 'Unassigned'}
        </span>
      );
    },
  },
  {
    id: 'alert_count',
    header: 'Alerts',
    accessorKey: 'alert_count',
    size: 70,
    cell: info => (
      <span className="text-[#8b949e] text-sm tabular-nums">{info.getValue<number>()}</span>
    ),
  },
  {
    id: 'created_at',
    header: 'Created',
    accessorFn: row => row.created_at,
    size: 110,
    cell: info => (
      <span className="text-[#8b949e] text-sm" title={info.getValue<string>()}>
        {formatRelativeTime(info.getValue<string>())}
      </span>
    ),
  },
  {
    id: 'updated_at',
    header: 'Updated',
    accessorFn: row => row.updated_at,
    size: 110,
    cell: info => (
      <span className="text-[#8b949e] text-sm" title={info.getValue<string>()}>
        {formatRelativeTime(info.getValue<string>())}
      </span>
    ),
  },
];

interface CaseListProps {
  onCreateNew: () => void;
}

export function CaseList({ onCreateNew }: CaseListProps) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { socket } = useWebSocket();
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<CaseSeverity | ''>('');
  const [statusFilter, setStatusFilter] = useState<CaseStatus | ''>('');
  const [sorting, setSorting] = useState<SortingState>([]);
  const [pagination, setPagination] = useState<PaginationState>({
    pageIndex: 0,
    pageSize: PAGE_SIZE,
  });

  const sortField: CaseSortField = (sorting[0]?.id as CaseSortField) ?? 'updated_at';

  // Convert TanStack sort to API sort (TanStack has desc=true/false)
  const apiSortDir: 'asc' | 'desc' = sorting.length > 0 && sorting[0].desc ? 'desc' : 'asc';

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['cases', {
      search: search || undefined,
      severity: severityFilter || undefined,
      status: statusFilter || undefined,
      sort_by: sortField,
      sort_dir: apiSortDir,
      limit: pagination.pageSize,
      offset: pagination.pageIndex * pagination.pageSize,
    }],
    queryFn: () =>
      getCases({
        search: search || undefined,
        severity: (severityFilter || undefined) as CaseSeverity | undefined,
        status: (statusFilter || undefined) as CaseStatus | undefined,
        sort_by: sortField,
        sort_dir: apiSortDir,
        limit: pagination.pageSize,
        offset: pagination.pageIndex * pagination.pageSize,
      }),
    refetchInterval: 30000, // Poll every 30s as fallback
    placeholderData: (prev) => prev,
  });

  // Listen for WebSocket incident updates
  useCallback(() => {
    if (!socket) return;
    const handler = () => {
      queryClient.invalidateQueries({ queryKey: ['cases'] });
    };
    socket.on('incident_update', handler);
    return () => {
      socket.off('incident_update', handler);
    };
  }, [socket, queryClient])();

  const table = useReactTable({
    data: data?.ok ? (data.data.data ?? []) : [],
    columns,
    state: {
      sorting,
      pagination,
    },
    onSortingChange: setSorting,
    onPaginationChange: setPagination,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    manualSorting: true,
    manualPagination: true,
    pageCount: data?.ok ? Math.ceil((data.data.meta?.total ?? 0) / pagination.pageSize) : -1,
  });

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    // Search is already in queryKey, refetch on submit
  };

  return (
    <div className="space-y-4">
      {/* Toolbar */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
        {/* Search */}
        <form onSubmit={handleSearchSubmit} className="flex-1 max-w-md">
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search cases by title or description..."
            className="w-full px-3 py-2 rounded-lg bg-[#0f1117] border border-[#30363d] text-[#e1e4e8] placeholder-[#6e7681] focus:border-[#a78bfa] focus:ring-1 focus:ring-[#a78bfa] outline-none text-sm transition-colors"
            aria-label="Search cases"
          />
        </form>

        {/* Filters */}
        <div className="flex items-center gap-2">
          <select
            value={severityFilter}
            onChange={e => setSeverityFilter(e.target.value as CaseSeverity | '')}
            className="px-3 py-2 rounded-lg bg-[#0f1117] border border-[#30363d] text-[#e1e4e8] text-sm focus:border-[#a78bfa] outline-none transition-colors"
            aria-label="Filter by severity"
          >
            <option value="">All Severities</option>
            {SEVERITY_OPTIONS.map(opt => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </select>

          <select
            value={statusFilter}
            onChange={e => setStatusFilter(e.target.value as CaseStatus | '')}
            className="px-3 py-2 rounded-lg bg-[#0f1117] border border-[#30363d] text-[#e1e4e8] text-sm focus:border-[#a78bfa] outline-none transition-colors"
            aria-label="Filter by status"
          >
            <option value="">All Statuses</option>
            {STATUS_OPTIONS.map(opt => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </select>

          <button
            type="button"
            onClick={onCreateNew}
            className="px-4 py-2 rounded-lg bg-[#a78bfa] text-white text-sm font-medium hover:bg-[#7c3aed] transition-colors"
          >
            + New Case
          </button>
        </div>
      </div>

      {/* Loading state */}
      {isLoading && !data && (
        <div className="rounded-lg border border-[#30363d] bg-[#161b22] overflow-hidden">
          <div className="animate-pulse p-4 space-y-3">
            {Array.from({ length: 8 }).map((_, i) => (
              <div key={i} className="h-10 bg-[#1c2129] rounded" />
            ))}
          </div>
        </div>
      )}

      {/* Error state */}
      {isError && (
        <div className="rounded-lg border border-[#f43f5e]/30 bg-[#f43f5e]/5 p-6 text-center">
          <p className="text-[#f43f5e] text-sm mb-3">
            {error instanceof Error ? error.message : 'Failed to load cases'}
          </p>
          <button
            type="button"
            onClick={() => refetch()}
            className="px-4 py-2 rounded-lg bg-[#f43f5e]/10 border border-[#f43f5e]/30 text-[#f43f5e] text-sm hover:bg-[#f43f5e]/20 transition-colors"
          >
            Retry
          </button>
        </div>
      )}

      {/* Empty state */}
      {!isLoading && !isError && data?.ok && (data.data.data ?? []).length === 0 && (
        <div className="rounded-lg border border-dashed border-[#30363d] bg-[#161b22] p-12 text-center">
          <div className="text-4xl mb-4">📋</div>
          <h3 className="text-lg font-medium text-[#e1e4e8] mb-2">No incidents found</h3>
          <p className="text-sm text-[#8b949e] max-w-md mx-auto mb-4">
            Cases are automatically created when alerts are correlated, or you can create one manually.
          </p>
          <button
            type="button"
            onClick={onCreateNew}
            className="px-4 py-2 rounded-lg bg-[#a78bfa] text-white text-sm font-medium hover:bg-[#7c3aed] transition-colors"
          >
            Create First Case
          </button>
        </div>
      )}

      {/* Table */}
      {data?.ok && (data.data.data ?? []).length > 0 && (
        <div className="rounded-lg border border-[#30363d] bg-[#161b22] overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full" role="table">
              <thead>
                {table.getHeaderGroups().map(headerGroup => (
                  <tr key={headerGroup.id} className="border-b border-[#30363d]">
                    {headerGroup.headers.map(header => (
                      <th
                        key={header.id}
                        className="px-4 py-3 text-left text-xs font-semibold text-[#8b949e] uppercase tracking-wider cursor-pointer select-none hover:text-[#e1e4e8] transition-colors"
                        style={{ width: header.getSize() }}
                        onClick={header.column.getToggleSortingHandler()}
                        aria-sort={
                          header.column.getIsSorted()
                            ? header.column.getIsSorted() === 'asc'
                              ? 'ascending'
                              : 'descending'
                            : 'none'
                        }
                      >
                        <span className="inline-flex items-center gap-1">
                          {flexRender(header.column.columnDef.header, header.getContext())}
                          {header.column.getIsSorted() && (
                            <span className="text-[#a78bfa]">
                              {header.column.getIsSorted() === 'asc' ? '▲' : '▼'}
                            </span>
                          )}
                        </span>
                      </th>
                    ))}
                  </tr>
                ))}
              </thead>
              <tbody>
                {table.getRowModel().rows.map(row => (
                  <tr
                    key={row.id}
                    className="border-b border-[#30363d] hover:bg-[#1c2129] cursor-pointer transition-colors"
                    onClick={() => navigate(`/investigate/cases/${row.original.id}`)}
                    tabIndex={0}
                    onKeyDown={e => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        navigate(`/investigate/cases/${row.original.id}`);
                      }
                    }}
                    role="row"
                  >
                    {row.getVisibleCells().map(cell => (
                      <td key={cell.id} className="px-4 py-3 text-sm">
                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <div className="flex items-center justify-between px-4 py-3 border-t border-[#30363d] text-sm text-[#8b949e]">
            <span>
              Showing {pagination.pageIndex * pagination.pageSize + 1}–
              {Math.min(
                (pagination.pageIndex + 1) * pagination.pageSize,
                data?.ok ? data.data.meta?.total ?? 0 : 0
              )}{' '}
              of {data?.ok ? data.data.meta?.total ?? 0 : 0}
            </span>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => table.previousPage()}
                disabled={!table.getCanPreviousPage()}
                className="px-3 py-1.5 rounded-lg bg-[#1c2129] border border-[#30363d] text-[#e1e4e8] disabled:opacity-40 disabled:cursor-not-allowed hover:bg-[#21262d] transition-colors text-sm"
              >
                Previous
              </button>
              <span className="px-2 text-[#8b949e]">
                Page {pagination.pageIndex + 1} of {table.getPageCount() || 1}
              </span>
              <button
                type="button"
                onClick={() => table.nextPage()}
                disabled={!table.getCanNextPage()}
                className="px-3 py-1.5 rounded-lg bg-[#1c2129] border border-[#30363d] text-[#e1e4e8] disabled:opacity-40 disabled:cursor-not-allowed hover:bg-[#21262d] transition-colors text-sm"
              >
                Next
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
