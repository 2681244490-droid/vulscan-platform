export interface User {
  id: string;
  username: string;
  email: string;
  role: string;
  is_active: boolean;
  created_at: string;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface LoginResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  user: User;
}

export interface RegisterRequest {
  username: string;
  email: string;
  password: string;
}

export interface RefreshTokenRequest {
  refresh_token: string;
}

export interface Target {
  id: string;
  name: string;
  url: string;
  description: string | null;
  status: 'active' | 'inactive' | 'scanning' | 'error';
  scan_frequency: string | null;
  last_scan_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface CreateTargetRequest {
  name: string;
  url: string;
  description?: string;
  scan_frequency?: string;
}

export interface ScanTask {
  id: string;
  name: string;
  target_ids: string[];
  target_names?: string[];
  target_count: number;
  status: TaskStatus;
  scan_type: ScanType;
  priority: TaskPriority;
  progress: number;
  concurrency: number;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface CreateScanTaskRequest {
  target_id: string;
  scan_type?: ScanType;
  priority?: TaskPriority;
  concurrency?: number;
  plugins?: string[];
}

export interface ScanProgress {
  task_id: string;
  progress: number;
  status: TaskStatus;
  current_target: string;
  message: string;
  vulnerabilities_found: number;
}

export interface Vulnerability {
  id: string;
  task_id: string;
  task_name?: string;
  target_id: string;
  target_url?: string;
  plugin_name: string;
  severity: VulnerabilitySeverity;
  title: string;
  description: string;
  payload: string | null;
  proof: string | null;
  remediation: string;
  cve: string | null;
  cvss_score: number | null;
  status: 'open' | 'fixed' | 'ignored' | 'verified';
  created_at: string;
  updated_at: string;
}

export interface Report {
  id: string;
  task_id: string;
  task_name: string;
  template: string | null;
  status: 'generating' | 'completed' | 'failed';
  summary: Record<string, unknown>;
  generated_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface ReportTemplate {
  id: string;
  name: string;
  description: string;
  icon: string;
}

export interface PaginatedResponse<T> {
  data: T[];
  page: number;
  page_size: number;
  total: number;
  total_pages: number;
}

export interface ErrorResponse {
  error: string;
  message: string;
  code: number;
  timestamp: string;
}

export interface DashboardStats {
  today_scans: number;
  high_risk_count: number;
  pending_fix_count: number;
  total_targets: number;
  scan_trend: TrendData[];
  vulnerability_distribution: DistributionData[];
  severity_distribution: DistributionData[];
}

export interface TrendData {
  date: string;
  count: number;
  high_risk: number;
  medium_risk: number;
  low_risk: number;
}

export interface DistributionData {
  name: string;
  value: number;
}

export type TaskStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled' | 'paused' | 'scanning' | 'queued';
export type ScanType = 'full' | 'quick' | 'custom';
export type TaskPriority = 'low' | 'medium' | 'high' | 'critical';
export type VulnerabilitySeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
