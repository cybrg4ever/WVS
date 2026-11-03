export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type ScanStatus = 'idle' | 'scanning' | 'complete';

export interface Vulnerability {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  description: string;
  location: string;
  evidence: string;
  remediation: string;
  cwe?: string;
  cvss?: number;
}

export interface ScanResult {
  target: string;
  startTime: Date;
  endTime: Date;
  duration: number;
  totalVulnerabilities: number;
  vulnerabilities: Vulnerability[];
  severityBreakdown: Record<Severity, number>;
  categoriesScanned: string[];
  pagesScanned: number;
  requestsMade: number;
}

export interface ScanConfig {
  url: string;
  scanType: 'quick' | 'full' | 'passive';
  categories: string[];
}
