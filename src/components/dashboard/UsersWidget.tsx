interface User {
  username: string;
  terminal: string;
  source_ip: string;
  activity: string;
}

interface UsersWidgetProps {
  users: User[];
  lastUpdated: string | null;
}

export function UsersWidget({ users, lastUpdated }: UsersWidgetProps) {
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs text-[#8b949e]">
          {users.length} user{users.length !== 1 ? 's' : ''} logged in
        </span>
        {lastUpdated && (
          <span className="text-[10px] text-[#6e7681]">{lastUpdated}</span>
        )}
      </div>

      {users.length === 0 ? (
        <div className="text-xs text-[#6e7681] text-center py-3">
          No logged-in users
        </div>
      ) : (
        <div className="max-h-[160px] overflow-y-auto space-y-1.5">
          {users.map((user, i) => (
            <div key={i} className="flex items-center gap-2 text-xs py-0.5 border-b border-[#21262d]/50 last:border-0">
              <span className="w-1.5 h-1.5 rounded-full bg-[#22c55e] flex-shrink-0" />
              <span className="font-medium text-[#e1e4e8] min-w-[60px]">{user.username}</span>
              <span className="text-[#6e7681] font-mono text-[10px]">{user.terminal}</span>
              <span className="text-[#8b949e] text-[10px] ml-auto truncate max-w-[100px]">
                {user.source_ip}
              </span>
              <span className="text-[#6e7681] text-[10px] truncate max-w-[100px]">
                {user.activity?.substring(0, 40) ?? '—'}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
