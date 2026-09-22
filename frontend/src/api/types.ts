export type Severity = 'OK' | 'INFO' | 'WARN' | 'HIGH' | 'CRITICAL' | 'ERROR'

export interface SessionStatus {
  required: boolean
  authenticated: boolean
  expires_at?: string | null
}

export interface Bootstrap {
  product: {
    name: string
    version: string
    description?: string
  }
  auth: SessionStatus
  runtime: {
    production: boolean
    demo_mode: boolean
  }
  capabilities: {
    scanner: boolean
    database: boolean
    dns_fix: boolean
    pdf: boolean
    monitoring_enabled?: boolean
    automatic_remediation?: boolean
  }
  operator: {
    org_name: string
  }
}

export interface DomainSummary {
  id?: number
  domain: string
  added_at?: string
  last_scan_at?: string | null
  last_grade?: string | null
  last_score?: number | null
  previous_grade?: string | null
  previous_score?: number | null
  notes?: string
  is_active?: number | boolean
}

export interface AlertRecord {
  id: number
  domain: string
  alert_type: string
  severity: Severity | string
  message: string
  details?: string
  created_at: string
  acknowledged?: number | boolean
}

export interface Statistics {
  total_scans?: number
  unique_domains?: number
  total_results?: number
  average_score?: number
  alert_count?: number
  score_stats?: {
    avg_score?: number | null
    min_score?: number | null
    max_score?: number | null
  }
  severity_distribution?: Record<string, number>
  grade_distribution?: Record<string, number>
}

export interface DashboardPayload {
  stats: Statistics
  domains: DomainSummary[]
  alerts: AlertRecord[]
  settings: Record<string, string | boolean | number>
}

export interface Evaluation {
  severity?: Severity | string
  severity_title?: string
  severity_description?: string
  score?: number
  grade?: string
  violations?: string | string[]
  violation_count?: number
  advice?: string
}

export interface ScanResult {
  domain: string
  saved: boolean
  scan?: Record<string, unknown>
  evaluation?: Evaluation
  remediation?: Array<Record<string, unknown>>
  error?: string
}

export interface ScanResponse {
  status: 'success' | 'error' | 'partial' | string
  count: number
  results: ScanResult[]
  persistence_skipped?: boolean
}

export interface DomainDetailResponse {
  domain: string
  result: Record<string, unknown>
  source: string
}

export interface DomainHistoryResponse {
  domain: string
  history: Array<Record<string, unknown>>
  count: number
}

export interface ManagedDomainsResponse {
  domains: DomainSummary[]
  count: number
  alert_count: number
}

export interface AlertsResponse {
  alerts: AlertRecord[]
  count: number
}

export interface SettingsResponse {
  settings: Record<string, string | boolean | number>
}
