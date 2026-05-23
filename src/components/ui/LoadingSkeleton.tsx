interface SkeletonProps {
  className?: string;
  lines?: number;
}

export function Skeleton({ className = '' }: SkeletonProps) {
  return (
    <div
      className={`animate-pulse rounded bg-[#21262d] ${className}`}
      role="status"
      aria-label="Loading"
    />
  );
}

export function SkeletonCard() {
  return (
    <div className="rounded-lg border border-[#30363d] bg-[#161b22] p-4 space-y-3">
      <Skeleton className="h-5 w-1/3" />
      <Skeleton className="h-4 w-full" />
      <Skeleton className="h-4 w-2/3" />
    </div>
  );
}

export function SkeletonTable({ rows = 5 }: { rows?: number }) {
  return (
    <div className="rounded-lg border border-[#30363d] bg-[#161b22] overflow-hidden">
      <div className="p-3 border-b border-[#30363d]">
        <Skeleton className="h-4 w-1/4" />
      </div>
      <div className="divide-y divide-[#30363d]">
        {Array.from({ length: rows }).map((_, i) => (
          <div key={i} className="p-3 flex gap-4">
            <Skeleton className="h-4 w-16" />
            <Skeleton className="h-4 flex-1" />
            <Skeleton className="h-4 w-24" />
          </div>
        ))}
      </div>
    </div>
  );
}

export function PageSkeleton() {
  return (
    <div className="space-y-4" role="status" aria-label="Loading page">
      <Skeleton className="h-8 w-48" />
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        <SkeletonCard />
        <SkeletonCard />
        <SkeletonCard />
      </div>
      <SkeletonTable rows={8} />
    </div>
  );
}
