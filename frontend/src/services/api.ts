/**
 * API Service for communicating with the backend
 * Handles all HTTP and WebSocket communications
 */

// When using Vite proxy, we use relative URLs. Otherwise, use the full URL.
const API_BASE_URL = import.meta.env.VITE_API_URL || '';
const WS_BASE_URL = import.meta.env.VITE_WS_URL || `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}`;

export interface ScanRequest {
  repo_url: string;
  github_token?: string;
}

export interface ScanResponse {
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
  scan_results: Array<{
    scanner: string;
    category: string;
    vulnerable: boolean;
    count: number;
    vulnerabilities: BackendVulnerability[];
  }>;
}

export interface PromptAnalysisResult {
  status: string;
  is_suspicious: boolean;
  threat_level: string;
  detected_patterns: Array<{
    type: string;
    pattern?: string;
    encoding?: string;
    context?: string;
  }>;
  pattern_count: number;
  recommendations: string[];
}

export interface ResponseAnalysisResult {
  status: string;
  is_compromised: boolean;
  jailbreak_indicators: string[];
  malicious_code: Array<{
    type: string;
    pattern: string;
  }>;
  recommendations: string[];
}

// WebSocket message types
export interface WSMessage {
  status?: string;
  progress?: number;
  error?: string;
  scan_id?: string;
  results?: ScanResponse['results'];
  timestamp?: string;
}

export type WSMessageHandler = (message: WSMessage) => void;

class ApiService {
  private baseUrl: string;
  private wsBaseUrl: string;
  private ws: WebSocket | null = null;

  constructor() {
    this.baseUrl = API_BASE_URL;
    this.wsBaseUrl = WS_BASE_URL;
  }

  /**
   * POST request helper
   */
  private async post<T>(endpoint: string, data: unknown): Promise<T> {
    const response = await fetch(`${this.baseUrl}${endpoint}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(data),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Unknown error' }));
      throw new Error(error.detail || `HTTP ${response.status}`);
    }

    return response.json();
  }

  /**
   * GET request helper
   */
  private async get<T>(endpoint: string): Promise<T> {
    const response = await fetch(`${this.baseUrl}${endpoint}`);

    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Unknown error' }));
      throw new Error(error.detail || `HTTP ${response.status}`);
    }

    return response.json();
  }

  // ========== Basic Scan Endpoints ==========

  /**
   * Start a repository scan (HTTP POST)
   */
  async scanRepository(request: ScanRequest): Promise<ScanResponse> {
    return this.post<ScanResponse>('/scan', request);
  }

  /**
   * Get a previous scan report
   */
  async getScanReport(scanId: string): Promise<ScanResponse> {
    return this.get<ScanResponse>(`/scan/${scanId}`);
  }

  /**
   * Health check
   */
  async healthCheck(): Promise<{ status: string }> {
    return this.get<{ status: string }>('/health');
  }

  // ========== WebSocket Scanning ==========

  /**
   * Start a scan with real-time progress updates via WebSocket
   */
  scanWithProgress(
    request: ScanRequest,
    onMessage: WSMessageHandler,
    onError?: (error: Error) => void,
    onComplete?: () => void
  ): () => void {
    // Close existing connection
    if (this.ws) {
      this.ws.close();
    }

    this.ws = new WebSocket(`${this.wsBaseUrl}/ws/scan`);

    this.ws.onopen = () => {
      this.ws?.send(JSON.stringify({
        action: 'start_scan',
        repo_url: request.repo_url,
        github_token: request.github_token,
      }));
    };

    this.ws.onmessage = (event) => {
      try {
        const message: WSMessage = JSON.parse(event.data);
        onMessage(message);
        
        // Check if scan is complete
        if (message.progress === 100 && message.results) {
          onComplete?.();
        }
        
        // Check for errors
        if (message.error) {
          onError?.(new Error(message.error));
        }
      } catch (e) {
        console.error('Failed to parse WebSocket message:', e);
      }
    };

    this.ws.onerror = () => {
      onError?.(new Error('WebSocket connection error'));
    };

    this.ws.onclose = () => {
      console.log('WebSocket connection closed');
    };

    // Return cleanup function
    return () => {
      this.ws?.close();
      this.ws = null;
    };
  }

  // ========== Garak LLM Security Endpoints ==========

  /**
   * Comprehensive LLM security scan
   */
  async garakComprehensiveScan(
    files: Record<string, { content: string }>,
    repoUrl?: string
  ): Promise<GarakScanResult> {
    return this.post<GarakScanResult>('/api/v1/garak/scan/comprehensive', {
      files,
      repo_url: repoUrl,
    });
  }

  /**
   * Analyze a prompt for potential attacks
   */
  async analyzePrompt(prompt: string): Promise<PromptAnalysisResult> {
    return this.post<PromptAnalysisResult>('/api/v1/garak/analyze/prompt', {
      prompt,
    });
  }

  /**
   * Analyze an LLM response for jailbreak indicators
   */
  async analyzeResponse(response: string): Promise<ResponseAnalysisResult> {
    return this.post<ResponseAnalysisResult>('/api/v1/garak/analyze/response', {
      response,
    });
  }

  /**
   * Scan for jailbreak patterns
   */
  async scanJailbreak(
    files: Record<string, { content: string }>
  ): Promise<GarakScanResult> {
    return this.post<GarakScanResult>('/api/v1/garak/scan/jailbreak', { files });
  }

  /**
   * Scan for encoding attacks
   */
  async scanEncodingAttacks(
    files: Record<string, { content: string }>
  ): Promise<GarakScanResult> {
    return this.post<GarakScanResult>('/api/v1/garak/scan/encoding', { files });
  }

  /**
   * Scan for latent injections
   */
  async scanLatentInjection(
    files: Record<string, { content: string }>
  ): Promise<GarakScanResult> {
    return this.post<GarakScanResult>('/api/v1/garak/scan/latent', { files });
  }

  /**
   * Scan for malware patterns
   */
  async scanMalware(
    files: Record<string, { content: string }>
  ): Promise<GarakScanResult> {
    return this.post<GarakScanResult>('/api/v1/garak/scan/malware', { files });
  }

  /**
   * Get attack payloads for testing
   */
  async getPayloads(payloadType?: string): Promise<{
    status: string;
    payload_types: string[];
    payload_count: number;
    payloads: Array<{
      content: string;
      type: string;
      description: string;
      severity: string;
    }>;
  }> {
    const endpoint = payloadType 
      ? `/api/v1/garak/payloads?payload_type=${payloadType}`
      : '/api/v1/garak/payloads';
    return this.get(endpoint);
  }

  /**
   * Check garak service health
   */
  async garakHealthCheck(): Promise<{
    status: string;
    service: string;
    scanners: string[];
    payload_types: string[];
  }> {
    return this.get('/api/v1/garak/health');
  }

  // ========== ML Security Endpoints ==========

  /**
   * Scan for unsafe model serialization
   */
  async scanSerialization(repoPath: string): Promise<unknown> {
    return this.post('/api/v1/scan/serialization', { repo_path: repoPath });
  }

  /**
   * Analyze model for backdoor indicators
   */
  async scanBackdoor(modelActivations: Record<string, number[]>): Promise<unknown> {
    return this.post('/api/v1/scan/backdoor', { model_activations: modelActivations });
  }

  /**
   * Analyze API endpoint for model extraction risk
   */
  async scanExtractionRisk(endpointConfig: unknown): Promise<unknown> {
    return this.post('/api/v1/scan/extraction', endpointConfig);
  }

  /**
   * Get vulnerability explanation
   */
  async getExplanation(
    vulnerabilityType: string,
    level: string = 'beginner'
  ): Promise<unknown> {
    return this.get(`/api/v1/explain/${vulnerabilityType}?level=${level}`);
  }
}

// Export singleton instance
export const api = new ApiService();

// Export class for testing
export { ApiService };
