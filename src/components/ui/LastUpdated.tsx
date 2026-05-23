import { useState, useEffect, useMemo } from 'react';

interface LastUpdatedProps {
  timestamp: number | null;
  onRefresh?: () => void;
}

export function LastUpdated({ timestamp, onRefresh }: LastUpdatedProps) {
  const [tick, setTick] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => setTick(n => n + 1), 1000);
    return () => clearInterval(interval);
  }, []);

  const text = useMemo(() => {
    if (!timestamp) return null;

    // eslint-disable-next-line react-hooks/purity -- tick dependency ensures re-computation every second
    const secondsAgo = Math.floor((Date.now() - timestamp) / 1000);
    if (secondsAgo < 5) return 'just now';
    if (secondsAgo < 60) return `${secondsAgo}s ago`;
    return `${Math.floor(secondsAgo / 60)}m ago`;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [timestamp, tick]);

  if (!timestamp) return null;

  return (
    <button
      type="button"
      onClick={onRefresh}
      className="text-xs text-[#6e7681] hover:text-[#8b949e] transition-colors cursor-pointer"
      title="Click to refresh"
    >
      Updated {text}
    </button>
  );
}
