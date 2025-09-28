
export enum ScanStatus {
  Pending = 'pending',
  RunningSubfinder = 'running_subfinder',
  RunningHttpx = 'running_httpx',
  RunningNuclei = 'running_nuclei',
  Completed = 'completed',
  Failed = 'failed',
}

export enum Severity {
  Critical = 'critical',
  High = 'high',
  Medium = 'medium',
  Low = 'low',
  Info = 'info',
  Unknown = 'unknown',
}

export interface Target {
  id: string;
  url: string;
  createdAt: string;
}

export interface Scan {
  id: string;
  domain: string;
  status: ScanStatus;
  createdAt: string;
  completedAt: string | null;
  vulnerabilities: Vulnerability[];
}

export interface Asset {
  id: string;
  host: string;
  ipAddress: string | null;
  technologies: Record<string, any>;
  ports: number[];
}

export interface Vulnerability {
  id: string;
  host: string;
  templateId: string;
  name: string;
  severity: Severity;
  description: string;
  timestamp: string;
}