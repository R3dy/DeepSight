// ── User & Auth ──
export interface User {
  id: number;
  username: string;
  is_admin: boolean;
}

export interface AuthStatus {
  user: User;
  token_expires: string;
  token_type: string;
}

export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  token: string;
  user: User;
  expires_at: string;
}

// ── Hosts ──
export interface HostStatus {
  hostname: string;
  status: 'online' | 'stale' | 'offline';
  last_seen: number;
  alert_count?: number;
}

export interface HostsResponse {
  hosts: Record<string, HostStatus>;
}

// ── Dashboard ──
export interface MemoryStats {
  total: number;
  available: number;
  used: number;
  free: number;
  buffers: number;
  cached: number;
  percent: number;
  total_gb: number;
  used_gb: number;
  available_gb: number;
  free_gb: number;
  cached_gb: number;
  buffers_gb: number;
  hard_used_gb: number;
  kernel_gb?: number;
  swap_total?: number;
  swap_used?: number;
  swap_percent?: number;
}

export interface CpuStats {
  percent: number;
  count: number;
  freq_current?: number;
  freq_max?: number;
  per_cpu?: number[];
  temperature?: number;
  load_avg?: {
    '1min': number;
    '5min': number;
    '15min': number;
  };
  uptime_seconds?: number;
  ctx_switches_per_sec?: number;
}

export interface GpuStats {
  name?: string;
  usage_percent?: number;
  vram_total?: number;
  vram_used?: number;
  vram_free?: number;
  temperature?: number;
  power_draw?: number;
  sclk_mhz?: number;
  mclk_mhz?: number;
}

export interface DiskStats {
  device: string;
  mountpoint: string;
  fstype: string;
  total_gb: number;
  used_gb: number;
  free_gb: number;
  percent: number;
  read_mbps?: number;
  write_mbps?: number;
  read_iops?: number;
  write_iops?: number;
}

export interface NetworkStats {
  interfaces?: Record<string, { rx_gb: number; tx_gb: number; rx_packets: number; tx_packets: number }>;
  tcp_established?: number;
  tcp_listen?: number;
  udp_count?: number;
  tcp_listeners?: Array<{ port: number; process: string; state: string }>;
  outbound_http?: Array<{ process: string; url: string; protocol: string }>;
  rx_mbps?: number;
  tx_mbps?: number;
}

export interface ProcessInfo {
  pid: number;
  name: string;
  username?: string;
  state?: string;
  cpu_percent?: number;
  mem_rss?: number;
  mem_percent?: number;
  threads?: number;
}

export interface HostStats {
  hostname: string;
  timestamp: number;
  memory: MemoryStats;
  cpu: CpuStats;
  gpu?: GpuStats;
  disks: DiskStats[];
  network?: NetworkStats;
  processes?: ProcessInfo[];
  users?: Array<{ username: string; terminal: string; source_ip: string; activity: string }>;
}

// ── Security ──
export interface Alert {
  id: number;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  category: string;
  source_ip?: string;
  source_host?: string;
  process_name?: string;
  process_pid?: number;
  mitre_technique?: string;
  timestamp: string;
  acknowledged: boolean;
}

export interface SecuritySummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  beaconing_count: number;
  auth_failures_1h: number;
  file_events_1h: number;
}

export interface BeaconingEvent {
  process_name: string;
  pid: number;
  interval_seconds: number;
  remote_host: string;
  remote_port: number;
  http_detail?: string;
  user_agent?: string;
  confidence: number;
  sample_count: number;
}

export interface AuthEvent {
  timestamp: string;
  event_type: string;
  username: string;
  source_ip: string;
  detail: string;
  failure_count?: number;
}

export interface FileEvent {
  timestamp: string;
  event_type: 'created' | 'modified' | 'deleted';
  path: string;
  process: string;
}

// ── Cluster / Overview ──
export interface ClusterHost {
  hostname: string;
  status: string;
  memory: MemoryStats;
  cpu: CpuStats;
  disks: DiskStats[];
  processes?: ProcessInfo[];
}

export interface ClusterData {
  hosts: Record<string, ClusterHost>;
}

// ── Process Detail ──
export interface ProcessDetail {
  found: boolean;
  name?: string;
  pid?: number;
  user?: string;
  state?: string;
  cmdline?: string;
  vm_rss_mb?: number;
  vm_size_mb?: number;
  vm_data_mb?: number;
  vm_stk_mb?: number;
  vm_exe_mb?: number;
  vm_lib_mb?: number;
  vm_swap_mb?: number;
  threads?: number;
  cpu_percent?: number;
  cpu_user_s?: number;
  cpu_system_s?: number;
  fd_count?: number;
  child_count?: number;
  voluntary_ctxt_switches?: number;
  nonvoluntary_ctxt_switches?: number;
  network_connections?: Array<{ proto: string; local: string; remote: string; state: string }>;
  fd_samples?: Array<{ fd: number; target: string }>;
  child_details?: Array<{ pid: number; name: string }>;
  environ?: Record<string, string>;
  error?: string;
}

// ── Deep Dive Data ──
export interface MeminfoDeep {
  [key: string]: number;
}

export interface MemoryPressureData {
  some_avg10?: number;
  some_avg60?: number;
  some_avg300?: number;
  full_avg10?: number;
  full_avg60?: number;
  full_avg300?: number;
}

export interface PssUssProcess {
  pid: number;
  user: string;
  name: string;
  state: string;
  threads: number;
  pss_mb: number;
  rss_mb: number;
  uss_mb: number;
  cpu_percent: number;
  cpu_user_s: number;
  cpu_system_s: number;
}

export interface DeepDiveData {
  hostname: string;
  timestamp: number;
  memory: MemoryStats;
  cpu: CpuStats;
  gpu?: GpuStats;
  disks: DiskStats[];
  processes?: ProcessInfo[];
  ram_processes?: ProcessInfo[];
  cpu_processes?: ProcessInfo[];
  meminfo?: MeminfoDeep;
  memory_pressure?: MemoryPressureData;
  swappiness?: number;
  hugepages_total?: number;
  hugepages_free?: number;
  hugepages_reserved?: number;
  pss_uss_processes?: PssUssProcess[];
  cpu_time_breakdown?: {
    user: number; nice: number; system: number; iowait: number;
    irq: number; softirq: number; steal: number; idle: number;
  };
  load_avg?: { '1min': number; '5min': number; '15min': number };
  uptime_seconds?: number;
  per_cpu?: number[];
  ctx_switches_per_sec?: number;
  network?: NetworkStats;
  network_deep?: NetworkStats;
}

// ── Security Dashboards ──
export interface AlertTimelineData {
  labels: string[];
  critical?: number[];
  high?: number[];
  medium?: number[];
  low?: number[];
  info?: number[];
  total: number;
}

export interface TopSourceIPs {
  labels: string[];
  counts: number[];
  total: number;
}

export interface MitreRadarData {
  labels: string[];
  counts: number[];
  total: number;
}

export interface SeverityDoughnutData {
  labels: string[];
  counts: number[];
  total: number;
}

export interface AgentHealthData {
  labels: string[];
  counts: number[];
  total_hosts: number;
  host_names: string[];
}

export interface EventDistributionData {
  labels: string[];
  counts: number[];
  total: number;
}

export interface SecurityDashboardData {
  alert_timeline: AlertTimelineData;
  top_source_ips: TopSourceIPs;
  mitre_radar: MitreRadarData;
  alert_severity: SeverityDoughnutData;
  agent_health: AgentHealthData;
  event_distribution: EventDistributionData;
}

// ── Threat Intel ──
export interface ThreatIntelFeed {
  name: string;
  status: 'loaded' | 'stale' | 'not_loaded' | 'error' | 'disabled';
  indicator_count: number;
  last_updated?: number;
  error_message?: string;
}

export interface ThreatIntelStatus {
  feeds: ThreatIntelFeed[];
  loaded_count: number;
  total_feeds: number;
  observed_ips: number;
  observed_domains: number;
}

// ── Syslog ──
export interface SyslogEvent {
  timestamp: string;
  severity: string;
  source_host: string;
  facility: string;
  message: string;
}

export interface SyslogResponse {
  events: SyslogEvent[];
  count: number;
  hosts: string[];
  facilities: string[];
}

// ── Search ──
export interface SearchResult {
  type: string;
  timestamp: string;
  severity?: string;
  host?: string;
  source_ip?: string;
  title?: string;
  description?: string;
  [key: string]: unknown;
}

export interface SearchResponse {
  results: SearchResult[];
  total: number;
  query_parsed?: Record<string, string>;
}

// ── Alert Stats ──
export interface AlertStats {
  by_severity: Record<string, number>;
  by_category: Record<string, number>;
  total: number;
}

// ── API ──
export interface ApiError {
  error: string;
  [key: string]: unknown;
}

export type ApiResponse<T> =
  | { ok: true; data: T }
  | { ok: false; error: string; status: number };

// ── MITRE ATT&CK Coverage ──
export interface AttackTechnique {
  id: string;
  name: string;
  covered: boolean;
  rules: string[];
}

export interface AttackTacticCoverage {
  tactic: string;
  tactic_id: string;
  techniques: AttackTechnique[];
  technique_count: number;
  covered_count: number;
  uncovered_count: number;
  coverage_pct: number;
}

export interface CoverageGap {
  technique_id: string;
  technique_name: string;
  tactic: string;
  tactic_id: string;
  recommendation: string;
}

export interface AttackCoverageData {
  tactics: AttackTacticCoverage[];
  gaps: CoverageGap[];
  overall_coverage_pct: number;
  total_techniques: number;
  total_covered: number;
  total_uncovered: number;
  generated_at: string;
}
