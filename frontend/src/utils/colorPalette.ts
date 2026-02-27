// frontend/src/utils/colorPalette.ts

/**
 * Fixed color palette for TrafficControl visualization
 * High contrast colors for accessibility
 */
export const TRAFFIC_CONTROL_COLORS = [
  '#3b82f6', // Blue
  '#10b981', // Green
  '#f59e0b', // Amber
  '#ef4444', // Red
  '#8b5cf6', // Purple
  '#ec4899', // Pink
  '#06b6d4', // Cyan
  '#84cc16', // Lime
] as const;

/**
 * Get color for TrafficControl by index
 */
export function getTrafficControlColor(index: number): string {
  return TRAFFIC_CONTROL_COLORS[index % TRAFFIC_CONTROL_COLORS.length];
}

/**
 * Get color for TrafficControl by name (consistent hash)
 */
export function getTrafficControlColorByName(name: string): string {
  let hash = 0;
  for (let i = 0; i < name.length; i++) {
    hash = ((hash << 5) - hash) + name.charCodeAt(i);
    hash = hash & hash;
  }
  return TRAFFIC_CONTROL_COLORS[Math.abs(hash) % TRAFFIC_CONTROL_COLORS.length];
}
