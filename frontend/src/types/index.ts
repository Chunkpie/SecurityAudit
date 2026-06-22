export type ScanStatus = 'pending' | 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
export type ScanType = 'full' | 'quick' | 'tls' | 'headers' | 'vulnerabilities' | 'source_code';
export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type DeploymentVerdict = 'GO' | 'GO_WITH_CONDITIONS' | 'NO_GO';
export type UserRole = 'owner' | 'admin' | 'member' | 'viewer';

export interface User {
  id: string;
  email: string;
  full_name: string;
  is_active: boolean;
  is_verified: boolean;
  avatar_url?: string;
  created_at: string;
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
  description?: string;
  plan: string;
  created_at: string;
}

export interface Scan {
  id: string;
  target_url: string;
  target_domain: string;
  scan_type: ScanType;
  status: ScanStatus;
  security_score?: number;
  verdict?: DeploymentVerdict;
  scan_metadata?: Record<string, unknown>;
  error_message?: string;
  started_at?: string;
  completed_at?: string;
  created_at: string;
  updated_at: string;
}

export interface Finding {
  id: string;
  scan_id: string;
  title: string;
  severity: FindingSeverity;
  category: string;
  description: string;
  evidence?: Record<string, unknown>;
  impact: string;
  remediation: string;
  reproduction_steps?: string;
  verification_steps?: string;
  cve_ids?: string[];
  cvss_score?: number;
  risk_score?: number;
  affected_url?: string;
  tool_name?: string;
  screenshot_path?: string;
  is_false_positive: boolean;
  is_resolved: boolean;
  created_at: string;
}

export interface FindingListResponse {
  items: Finding[];
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface ScanListResponse {
  items: Scan[];
  total: number;
  page: number;
  per_page: number;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

export interface ScanCreate {
  target_url: string;
  scan_type: ScanType;
  organization_id: string;
  scan_config?: Record<string, unknown>;
  consent_confirmed: boolean;
  scheduled?: boolean;
  schedule_frequency?: 'daily' | 'weekly' | 'monthly';
}

export interface ScanSummary {
  scan_id: string;
  status: ScanStatus;
  verdict?: DeploymentVerdict;
  security_score?: number;
  target_url: string;
  started_at?: string;
  completed_at?: string;
  findings_summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}
