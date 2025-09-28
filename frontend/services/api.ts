import type { Scan, Asset, Vulnerability } from '../types';

const API_BASE_URL = '/api/v1'; // Proxied by Nginx in Docker setup

// --- snake_case to camelCase Conversion ---
const toCamel = (s: string): string => {
  return s.replace(/([-_][a-z])/ig, ($1) => {
    return $1.toUpperCase()
      .replace('-', '')
      .replace('_', '');
  });
};

const isObject = (o: any): o is object => {
  return o === Object(o) && !Array.isArray(o) && typeof o !== 'function';
};

const convertKeysToCamelCase = (o: any): any => {
  if (isObject(o)) {
    const n: { [key: string]: any } = {};
    Object.keys(o)
      .forEach((k) => {
        n[toCamel(k)] = convertKeysToCamelCase((o as any)[k]);
      });
    return n;
  } else if (Array.isArray(o)) {
    return o.map((i) => {
      return convertKeysToCamelCase(i);
    });
  }
  return o;
};
// --- End Conversion ---

async function http<T>(path: string, config: RequestInit): Promise<T> {
  const request = new Request(`${API_BASE_URL}${path}`, config);
  const response = await fetch(request);

  if (!response.ok) {
    const errorBody = await response.json().catch(() => ({ message: 'An unknown error occurred' }));
    throw new Error(errorBody.detail?.[0]?.msg || errorBody.detail || 'Network response was not ok');
  }

  if (response.status === 204 || response.headers.get('content-length') === '0') {
    return {} as T;
  }

  const data = await response.json();
  return convertKeysToCamelCase(data) as T;
}


export const api = {
  async getScans(): Promise<Scan[]> {
    const scans = await http<Scan[]>('/scans/', { method: 'GET' });
    return scans.sort((a,b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  },

  async startScan(domain: string): Promise<Scan> {
    // FastAPI/Pydantic expects snake_case for field names.
    return await http<Scan>('/scans/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain: domain }),
    });
  },

  async getScanDetails(scanId: string): Promise<{ scan: Scan; assets: Asset[]; vulnerabilities: Vulnerability[] }> {
    // A single, more efficient endpoint to get all details at once.
    return await http<{ scan: Scan; assets: Asset[]; vulnerabilities: Vulnerability[] }>(`/scans/${scanId}/details`, { method: 'GET' });
  },

  async deleteScan(scanId: number): Promise<void> {
    return await http<void>(`/scans/${scanId}`, { method: 'DELETE' });
  },

  async getReport(scanId: number): Promise<string> {
    return await http<string>(`/scans/${scanId}/report`, { method: 'GET' });
  }
};