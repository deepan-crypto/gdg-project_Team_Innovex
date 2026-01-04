export type VulnerabilityType =
  | 'prompt_injection'
  | 'hardcoded_secrets'
  | 'sql_injection'
  | 'xss'
  | 'dependency'
  | 'unsafe_llm_output';

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
}

export interface ScanRequest {
  repo_url: string;
  github_token?: string;
}
