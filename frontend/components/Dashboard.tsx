import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { api } from '../services/api';
import type { Scan } from '../types';
import ScanStatusBadge from './ScanStatusBadge';
import Spinner from './Spinner';

interface DashboardProps {
  onSelectScan: (scan: Scan) => void;
}

type SortField = 'domain' | 'status' | 'createdAt' | 'completedAt';
type SortDirection = 'asc' | 'desc';

const ScanRow: React.FC<{
  scan: Scan;
  onSelectScan: (scan: Scan) => void;
  onDeleteScan: (scanId: number) => void;
  onRerunScan: (scan: Scan) => void;
  onGenerateReport: (scanId: number) => void;
}> = ({ scan, onSelectScan, onDeleteScan, onRerunScan, onGenerateReport }) => (
  <tr className="bg-gray-800/50 hover:bg-gray-700/50 transition-all duration-200 cursor-pointer group">
    <td className="p-4 font-mono text-blue-400 hover:text-blue-300" onClick={() => onSelectScan(scan)}>
      {scan.domain}
    </td>
    <td className="p-4" onClick={() => onSelectScan(scan)}>
      <ScanStatusBadge status={scan.status} />
    </td>
    <td className="p-4 text-gray-300 hidden sm:table-cell" onClick={() => onSelectScan(scan)}>
      {new Date(scan.createdAt).toLocaleString()}
    </td>
    <td className="p-4 text-gray-300 hidden md:table-cell" onClick={() => onSelectScan(scan)}>
      {scan.completedAt ? new Date(scan.completedAt).toLocaleString() : 'In Progress'}
    </td>
    <td className="p-4">
      <div className="flex items-center space-x-2">
        <button
          onClick={(e) => { e.stopPropagation(); onGenerateReport(scan.id); }}
          className="p-2 bg-green-600 hover:bg-green-500 text-white rounded transition-colors"
          title="Generate report"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
          </svg>
        </button>
        <button
          onClick={(e) => { e.stopPropagation(); onRerunScan(scan); }}
          className="p-1 text-gray-400 hover:text-blue-400 transition-colors"
          title="Rerun scan"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
        </button>
        <button
          onClick={(e) => { e.stopPropagation(); onDeleteScan(scan.id); }}
          className="p-1 text-gray-400 hover:text-red-400 transition-colors"
          title="Delete scan"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
          </svg>
        </button>
      </div>
    </td>
  </tr>
);

const Dashboard: React.FC<DashboardProps> = ({ onSelectScan }) => {
  const [domain, setDomain] = useState('');
  const [scans, setScans] = useState<Scan[]>([]);
  const [filteredScans, setFilteredScans] = useState<Scan[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [sortField, setSortField] = useState<SortField>('createdAt');
  const [sortDirection, setSortDirection] = useState<SortDirection>('desc');

  const stats = useMemo(() => {
    const total = scans.length;
    const completed = scans.filter(s => s.status === 'completed').length;
    const running = scans.filter(s => s.status === 'running').length;
    const failed = scans.filter(s => s.status === 'failed').length;
    return { total, completed, running, failed };
  }, [scans]);

  const fetchScans = useCallback(async () => {
    try {
      const fetchedScans = await api.getScans();
      setScans(fetchedScans);
    } catch (error) {
      console.error("Failed to fetch scans:", error);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchScans();
    const interval = setInterval(fetchScans, 5000);
    return () => clearInterval(interval);
  }, [fetchScans]);

  useEffect(() => {
    let filtered = scans.filter(scan => {
      const matchesSearch = scan.domain.toLowerCase().includes(searchTerm.toLowerCase());
      const matchesStatus = statusFilter === 'all' || scan.status === statusFilter;
      return matchesSearch && matchesStatus;
    });

    filtered.sort((a, b) => {
      let aVal: any = a[sortField];
      let bVal: any = b[sortField];

      if (sortField === 'createdAt' || sortField === 'completedAt') {
        aVal = new Date(aVal || 0).getTime();
        bVal = new Date(bVal || 0).getTime();
      }

      if (sortDirection === 'asc') {
        return aVal > bVal ? 1 : -1;
      } else {
        return aVal < bVal ? 1 : -1;
      }
    });

    setFilteredScans(filtered);
  }, [scans, searchTerm, statusFilter, sortField, sortDirection]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!domain.trim() || isSubmitting) return;

    setIsSubmitting(true);
    try {
      await api.startScan(domain);
      setDomain('');
      await fetchScans();
    } catch (error) {
      console.error("Failed to start scan:", error);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDeleteScan = async (scanId: number) => {
    if (!confirm('Are you sure you want to delete this scan?')) return;

    try {
      await api.deleteScan(scanId);
      await fetchScans();
    } catch (error) {
      console.error("Failed to delete scan:", error);
    }
  };

  const handleGenerateReport = async (scanId: number) => {
    try {
      const report = await api.getReport(scanId);
      // Create a blob and download the report
      const blob = new Blob([report], { type: 'text/markdown' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `bug-bounty-report-${scanId}.md`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (error) {
      console.error("Failed to generate report:", error);
      alert("Failed to generate report. Please try again.");
    }
  };

  const handleRerunScan = async (scan: Scan) => {
    try {
      await api.startScan(scan.domain);
      await fetchScans();
    } catch (error) {
      console.error("Failed to rerun scan:", error);
    }
  };

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('desc');
    }
  };

  return (
    <div className="space-y-6">
      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-gradient-to-br from-blue-900/50 to-blue-800/50 p-4 rounded-lg border border-blue-700/50">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-blue-300 text-sm font-medium">Total Scans</p>
              <p className="text-2xl font-bold text-white">{stats.total}</p>
            </div>
            <svg className="w-8 h-8 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
            </svg>
          </div>
        </div>
        <div className="bg-gradient-to-br from-green-900/50 to-green-800/50 p-4 rounded-lg border border-green-700/50">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-green-300 text-sm font-medium">Completed</p>
              <p className="text-2xl font-bold text-white">{stats.completed}</p>
            </div>
            <svg className="w-8 h-8 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
        </div>
        <div className="bg-gradient-to-br from-yellow-900/50 to-yellow-800/50 p-4 rounded-lg border border-yellow-700/50">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-yellow-300 text-sm font-medium">Running</p>
              <p className="text-2xl font-bold text-white">{stats.running}</p>
            </div>
            <svg className="w-8 h-8 text-yellow-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
        </div>
        <div className="bg-gradient-to-br from-red-900/50 to-red-800/50 p-4 rounded-lg border border-red-700/50">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-red-300 text-sm font-medium">Failed</p>
              <p className="text-2xl font-bold text-white">{stats.failed}</p>
            </div>
            <svg className="w-8 h-8 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
            </svg>
          </div>
        </div>
      </div>

      {/* Start New Scan */}
      <div className="bg-gray-800/50 p-6 rounded-lg border border-gray-700/50 backdrop-blur-sm">
        <h2 className="text-xl font-semibold mb-4 text-white flex items-center">
          <svg className="w-5 h-5 mr-2 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          Start New Scan
        </h2>
        <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row gap-4">
          <input
            type="text"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="example.com"
            className="flex-grow bg-gray-900/50 border border-gray-600 rounded-lg px-4 py-3 text-white placeholder-gray-400 focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
            disabled={isSubmitting}
            required
          />
          <button
            type="submit"
            className="bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 text-white font-semibold py-3 px-6 rounded-lg transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center shadow-lg"
            disabled={isSubmitting}
          >
            {isSubmitting ? <Spinner /> : (
              <>
                <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
                Scan Target
              </>
            )}
          </button>
        </form>
      </div>

      {/* Scan History */}
      <div className="bg-gray-800/50 p-6 rounded-lg border border-gray-700/50 backdrop-blur-sm">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between mb-6">
          <h2 className="text-xl font-semibold text-white flex items-center mb-4 lg:mb-0">
            <svg className="w-5 h-5 mr-2 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
            </svg>
            Scan History
          </h2>

          {/* Filters */}
          <div className="flex flex-col sm:flex-row gap-3">
            <input
              type="text"
              placeholder="Search domains..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-gray-900/50 border border-gray-600 rounded-lg px-3 py-2 text-white placeholder-gray-400 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-gray-900/50 border border-gray-600 rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="all">All Status</option>
              <option value="running">Running</option>
              <option value="completed">Completed</option>
              <option value="failed">Failed</option>
            </select>
          </div>
        </div>

        {isLoading ? (
          <div className="flex justify-center p-12"><Spinner size="lg"/></div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead className="border-b border-gray-600">
                <tr>
                  <th className="p-4 font-semibold text-gray-300 cursor-pointer hover:text-white transition-colors" onClick={() => handleSort('domain')}>
                    Target {sortField === 'domain' && (sortDirection === 'asc' ? '↑' : '↓')}
                  </th>
                  <th className="p-4 font-semibold text-gray-300 cursor-pointer hover:text-white transition-colors" onClick={() => handleSort('status')}>
                    Status {sortField === 'status' && (sortDirection === 'asc' ? '↑' : '↓')}
                  </th>
                  <th className="p-4 font-semibold text-gray-300 hidden sm:table-cell cursor-pointer hover:text-white transition-colors" onClick={() => handleSort('createdAt')}>
                    Started {sortField === 'createdAt' && (sortDirection === 'asc' ? '↑' : '↓')}
                  </th>
                  <th className="p-4 font-semibold text-gray-300 hidden md:table-cell cursor-pointer hover:text-white transition-colors" onClick={() => handleSort('completedAt')}>
                    Completed {sortField === 'completedAt' && (sortDirection === 'asc' ? '↑' : '↓')}
                  </th>
                  <th className="p-4 font-semibold text-gray-300">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredScans.length > 0 ? (
                  filteredScans.map(scan => (
                    <ScanRow
                      key={scan.id}
                      scan={scan}
                      onSelectScan={onSelectScan}
                      onDeleteScan={handleDeleteScan}
                      onRerunScan={handleRerunScan}
                      onGenerateReport={handleGenerateReport}
                    />
                  ))
                ) : (
                  <tr>
                    <td colSpan={5} className="text-center p-12 text-gray-400">
                      <svg className="w-12 h-12 mx-auto mb-4 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.172 16.172a4 4 0 015.656 0M9 12h6m-6-4h6m2 5.291A7.962 7.962 0 0112 15c-2.34 0-4.29-.966-5.5-2.5" />
                      </svg>
                      No scans found. Start one above!
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

export default Dashboard;