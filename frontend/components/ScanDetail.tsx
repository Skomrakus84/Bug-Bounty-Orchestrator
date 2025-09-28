import React, { useState, useEffect, useMemo, useCallback } from 'react';
import type { Scan, Asset, Vulnerability } from '../types';
import { ScanStatus, Severity } from '../types';
import { api } from '../services/api';
import ScanStatusBadge from './ScanStatusBadge';
import SeverityBadge from './SeverityBadge';
import Spinner from './Spinner';

interface ScanDetailProps {
  scan: Scan;
  onBack: () => void;
}

interface ScanDetailProps {
  scan: Scan;
  onBack: () => void;
}

const ScanProgress: React.FC<{ status: ScanStatus }> = ({ status }) => {
    const steps = useMemo(() => [
        { name: 'Subdomain Enumeration', status: ScanStatus.RunningSubfinder, icon: '🔍' },
        { name: 'HTTP Probe', status: ScanStatus.RunningHttpx, icon: '🌐' },
        { name: 'Vulnerability Scan', status: ScanStatus.RunningNuclei, icon: '🛡️' },
        { name: 'Reporting', status: ScanStatus.Completed, icon: '📊' }
    ], []);

    const getStepState = (stepStatus: ScanStatus) => {
        const currentStatusIndex = Object.values(ScanStatus).indexOf(status);
        const stepStatusIndex = Object.values(ScanStatus).indexOf(stepStatus);

        if (status === ScanStatus.Completed || currentStatusIndex > stepStatusIndex) {
            return 'completed';
        }
        if (currentStatusIndex === stepStatusIndex) {
            return 'current';
        }
        return 'upcoming';
    };

    return (
        <div className="bg-gray-800/50 p-6 rounded-lg border border-gray-700/50">
            <h3 className="text-lg font-semibold text-white mb-6 flex items-center">
                <svg className="w-5 h-5 mr-2 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                </svg>
                Scan Progress
            </h3>
            <nav aria-label="Progress">
                <ol role="list" className="flex items-center justify-center">
                    {steps.map((step, stepIdx) => (
                        <li key={step.name} className={`relative flex flex-col items-center ${stepIdx !== steps.length - 1 ? 'flex-1' : ''}`}>
                            {(() => {
                                const state = getStepState(step.status);
                                if (state === 'completed') {
                                    return (
                                        <>
                                            {stepIdx !== steps.length - 1 && (
                                                <div className="absolute top-4 left-1/2 w-full h-0.5 bg-green-500" style={{ transform: 'translateX(50%)' }} />
                                            )}
                                            <div className="relative flex h-10 w-10 items-center justify-center rounded-full bg-green-500 shadow-lg">
                                                <span className="text-white text-lg">{step.icon}</span>
                                            </div>
                                        </>
                                    );
                                } else if (state === 'current') {
                                    return (
                                        <>
                                            {stepIdx !== steps.length - 1 && (
                                                <div className="absolute top-4 left-1/2 w-full h-0.5 bg-gray-600" style={{ transform: 'translateX(50%)' }} />
                                            )}
                                            <div className="relative flex h-10 w-10 items-center justify-center rounded-full border-2 border-blue-500 bg-gray-800 shadow-lg">
                                                <span className="absolute h-3 w-3 rounded-full bg-blue-500 animate-ping" />
                                                <span className="relative h-3 w-3 rounded-full bg-blue-500" />
                                            </div>
                                        </>
                                    );
                                } else {
                                    return (
                                        <>
                                            {stepIdx !== steps.length - 1 && (
                                                <div className="absolute top-4 left-1/2 w-full h-0.5 bg-gray-600" style={{ transform: 'translateX(50%)' }} />
                                            )}
                                            <div className="relative flex h-10 w-10 items-center justify-center rounded-full border-2 border-gray-600 bg-gray-700" />
                                        </>
                                    );
                                }
                            })()}
                            <div className="mt-3 text-center">
                                <div className={`text-xs font-medium ${getStepState(step.status) === 'completed' ? 'text-green-400' : getStepState(step.status) === 'current' ? 'text-blue-400' : 'text-gray-500'}`}>
                                    {step.name}
                                </div>
                            </div>
                        </li>
                    ))}
                </ol>
            </nav>
        </div>
    );
};

const severityStyles: Record<Severity, { border: string; bg: string; icon: string }> = {
  [Severity.Critical]: { border: 'border-red-500', bg: 'bg-red-900/20', icon: '🚨' },
  [Severity.High]: { border: 'border-orange-500', bg: 'bg-orange-900/20', icon: '⚠️' },
  [Severity.Medium]: { border: 'border-yellow-500', bg: 'bg-yellow-900/20', icon: '⚡' },
  [Severity.Low]: { border: 'border-blue-500', bg: 'bg-blue-900/20', icon: 'ℹ️' },
  [Severity.Info]: { border: 'border-gray-500', bg: 'bg-gray-900/20', icon: '📋' },
  [Severity.Unknown]: { border: 'border-gray-500', bg: 'bg-gray-900/20', icon: '❓' },
};

const VulnerabilityCard: React.FC<{ vuln: Vulnerability }> = ({ vuln }) => {
  const style = severityStyles[vuln.severity] || severityStyles[Severity.Unknown];

  return (
    <div className={`p-4 rounded-lg border-l-4 ${style.border} ${style.bg} hover:bg-opacity-30 transition-all duration-200`}>
      <div className="flex justify-between items-start mb-2">
        <div className="flex items-start space-x-3">
          <span className="text-lg">{style.icon}</span>
          <div className="flex-1">
            <h4 className="font-semibold text-white text-sm leading-tight">{vuln.name}</h4>
            <p className="text-blue-400 text-xs font-mono mt-1">{vuln.host}</p>
          </div>
        </div>
        <SeverityBadge severity={vuln.severity} />
      </div>
      <p className="text-gray-300 text-sm leading-relaxed">{vuln.description}</p>
      {vuln.templateId && (
        <div className="mt-2 pt-2 border-t border-gray-700">
          <p className="text-xs text-gray-500 font-mono">Template: {vuln.templateId}</p>
        </div>
      )}
    </div>
  );
};


const ScanDetail: React.FC<ScanDetailProps> = ({ scan: initialScan, onBack }) => {
  const [scan, setScan] = useState<Scan | undefined>(initialScan);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>(initialScan.vulnerabilities || []);
  const [isLoading, setIsLoading] = useState(false);

  if (!scan && isLoading) {
    return (
      <div className="flex justify-center items-center p-10">
        <Spinner size="lg" />
        <p className="ml-4">Loading scan details...</p>
      </div>
    );
  }
  
  if (!scan) {
      return (
          <div>
              <button onClick={onBack} className="text-brand-primary hover:underline mb-4">&larr; Back to Dashboard</button>
              <p className="text-center text-red-500">Could not load scan details.</p>
          </div>
      )
  }

  const stats = useMemo(() => {
    const critical = vulnerabilities.filter(v => v.severity === Severity.Critical).length;
    const high = vulnerabilities.filter(v => v.severity === Severity.High).length;
    const medium = vulnerabilities.filter(v => v.severity === Severity.Medium).length;
    const low = vulnerabilities.filter(v => v.severity === Severity.Low).length;
    const info = vulnerabilities.filter(v => v.severity === Severity.Info).length;
    return { critical, high, medium, low, info, total: vulnerabilities.length };
  }, [vulnerabilities]);

  return (
    <div className="space-y-6">
      {/* Header with Back Button */}
      <div className="flex items-center justify-between">
        <button
          onClick={onBack}
          className="flex items-center space-x-2 text-blue-400 hover:text-blue-300 transition-colors"
        >
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
          </svg>
          <span>Back to Dashboard</span>
        </button>

        <div className="flex items-center space-x-4">
          <div className="text-right">
            <h1 className="text-2xl font-bold text-white">{scan.domain}</h1>
            <p className="text-gray-400 text-sm">Scan #{scan.id}</p>
          </div>
          <ScanStatusBadge status={scan.status} />
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
        <div className="bg-gradient-to-br from-red-900/50 to-red-800/50 p-4 rounded-lg border border-red-700/50">
          <div className="text-center">
            <p className="text-red-300 text-sm font-medium">Critical</p>
            <p className="text-2xl font-bold text-white">{stats.critical}</p>
          </div>
        </div>
        <div className="bg-gradient-to-br from-orange-900/50 to-orange-800/50 p-4 rounded-lg border border-orange-700/50">
          <div className="text-center">
            <p className="text-orange-300 text-sm font-medium">High</p>
            <p className="text-2xl font-bold text-white">{stats.high}</p>
          </div>
        </div>
        <div className="bg-gradient-to-br from-yellow-900/50 to-yellow-800/50 p-4 rounded-lg border border-yellow-700/50">
          <div className="text-center">
            <p className="text-yellow-300 text-sm font-medium">Medium</p>
            <p className="text-2xl font-bold text-white">{stats.medium}</p>
          </div>
        </div>
        <div className="bg-gradient-to-br from-blue-900/50 to-blue-800/50 p-4 rounded-lg border border-blue-700/50">
          <div className="text-center">
            <p className="text-blue-300 text-sm font-medium">Low</p>
            <p className="text-2xl font-bold text-white">{stats.low}</p>
          </div>
        </div>
        <div className="bg-gradient-to-br from-gray-900/50 to-gray-800/50 p-4 rounded-lg border border-gray-700/50">
          <div className="text-center">
            <p className="text-gray-300 text-sm font-medium">Info</p>
            <p className="text-2xl font-bold text-white">{stats.info}</p>
          </div>
        </div>
        <div className="bg-gradient-to-br from-purple-900/50 to-purple-800/50 p-4 rounded-lg border border-purple-700/50">
          <div className="text-center">
            <p className="text-purple-300 text-sm font-medium">Total</p>
            <p className="text-2xl font-bold text-white">{stats.total}</p>
          </div>
        </div>
      </div>

      {/* Scan Progress */}
      <ScanProgress status={scan.status} />

      {/* Scan Details */}
      <div className="bg-gray-800/50 p-6 rounded-lg border border-gray-700/50">
        <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
          <svg className="w-5 h-5 mr-2 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          Scan Details
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
          <div>
            <p className="text-gray-400">Started:</p>
            <p className="text-white font-mono">{new Date(scan.createdAt).toLocaleString()}</p>
          </div>
          <div>
            <p className="text-gray-400">Completed:</p>
            <p className="text-white font-mono">{scan.completedAt ? new Date(scan.completedAt).toLocaleString() : 'In Progress'}</p>
          </div>
          <div>
            <p className="text-gray-400">Duration:</p>
            <p className="text-white font-mono">
              {scan.completedAt
                ? `${Math.round((new Date(scan.completedAt).getTime() - new Date(scan.createdAt).getTime()) / 1000 / 60)} minutes`
                : `${Math.round((Date.now() - new Date(scan.createdAt).getTime()) / 1000 / 60)} minutes (running)`
              }
            </p>
          </div>
          <div>
            <p className="text-gray-400">Target:</p>
            <p className="text-white font-mono">{scan.target.domainName}</p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Assets */}
        <div className="bg-gray-800/50 p-6 rounded-lg border border-gray-700/50">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
            <svg className="w-5 h-5 mr-2 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
            </svg>
            Discovered Assets ({assets.length})
          </h3>
          {assets.length > 0 ? (
            <div className="overflow-auto max-h-96">
              <table className="w-full text-left text-sm">
                <thead className="sticky top-0 bg-gray-800/50">
                  <tr>
                    <th className="p-3 font-semibold text-gray-300">Host</th>
                    <th className="p-3 font-semibold text-gray-300">IP Address</th>
                    <th className="p-3 font-semibold text-gray-300">Ports</th>
                  </tr>
                </thead>
                <tbody>
                  {assets.map(asset => (
                                  <tr key={asset.id} className="border-t border-gray-700">
                                      <td className="p-2 font-mono text-brand-primary">{asset.host}</td>
                                      <td className="p-2 font-mono text-brand-secondary">{asset.ipAddress}</td>
                                  </tr>
                              ))}
                          </tbody>
                      </table>
                  </div>
              ) : (
                  <p className="text-brand-secondary text-center py-4">No assets discovered yet.</p>
              )}
          </div>

        {/* Vulnerabilities */}
        <div className="bg-gray-800/50 p-6 rounded-lg border border-gray-700/50">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
            <svg className="w-5 h-5 mr-2 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
            </svg>
            Vulnerabilities ({vulnerabilities.length})
          </h3>
          {vulnerabilities.length > 0 ? (
            <div className="space-y-3 max-h-96 overflow-auto">
              {vulnerabilities
                .sort((a,b) => Object.values(Severity).indexOf(a.severity) - Object.values(Severity).indexOf(b.severity))
                .map(vuln => <VulnerabilityCard key={vuln.id} vuln={vuln} />)
              }
            </div>
          ) : (
            <div className="text-center py-8">
              <svg className="w-12 h-12 mx-auto mb-4 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <p className="text-gray-400">No vulnerabilities found yet.</p>
              <p className="text-gray-500 text-sm mt-1">Great! Your target appears to be secure.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ScanDetail;