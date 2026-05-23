const PALETTE = [
  '#8b5cf6', '#06b6d4', '#10b981', '#f59e0b', '#f97316',
  '#ef4444', '#ec4899', '#6366f1', '#14b8a6', '#84cc16',
];

export function getColor(index: number): string {
  return PALETTE[index % PALETTE.length];
}
