export type VulnerabilityType =
  | 'prompt_injection'
  | 'hardcoded_secrets'
  | 'sql_injection'
  | 'xss'
  | 'dependency'
  | 'unsafe_llm_output'
  | 'jailbreak'
  | 'encoding_attack'
  | 'latent_injection'
  | 'malware'
  | 'dan_attack'
  | 'shell_execution'
  | 'data_exfiltration';

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Vulnerability {
  id: string;
  type: VulnerabilityType;
  severity: SeverityLevel;
  title: string;
  description: string;
  file_path: string;
  line_number: number;
  code_snippet: string;
  explanation: string;
  risk: string;
  fix: string;
  references?: string[];
  owasp_category?: string;
}

export interface ScanResult {
  scan_id: string;
  repo_url: string;
  scan_date: string;
  status: 'pending' | 'scanning' | 'completed' | 'failed';
  total_files_scanned: number;
  vulnerabilities: Vulnerability[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  owasp_mapping?: Record<string, number>;
  recommendations?: string[];
}

export interface ScanRequest {
  repo_url: string;
  github_token?: string;
}

// Backend response types
export interface BackendScanResponse {
  scan_id: string;
  repo_url: string;
  timestamp: string;
  results: {
    prompt_injection: ScannerResult;
    secrets: ScannerResult;
    sql_xss: ScannerResult;
    dependencies: ScannerResult;
  };
  report_path: string;
}

export interface ScannerResult {
  vulnerable: boolean;
  count: number;
  vulnerabilities: BackendVulnerability[];
}

export interface BackendVulnerability {
  file: string;
  line: number;
  type: string;
  severity: string;
  description: string;
  code_snippet?: string;
  why_dangerous?: string;
  fix?: string;
}

// Garak LLM security types
export interface GarakScanResult {
  status: string;
  repo_url: string;
  total_vulnerabilities: number;
  severity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  owasp_mapping: Record<string, number>;
  summary: string;
  recommendations: string[];
  scan_results: GarakScannerResult[];
}

export interface GarakScannerResult {
  scanner: string;
  category: string;
  vulnerable: boolean;
  count: number;
  vulnerabilities: BackendVulnerability[];
}

// WebSocket message types
export interface WSMessage {
  status?: string;
  progress?: number;
  error?: string;
  scan_id?: string;
  results?: BackendScanResponse['results'];
  timestamp?: string;
}
