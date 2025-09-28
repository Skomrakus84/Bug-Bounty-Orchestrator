
import React from 'react';
import { ScanStatus } from '../types';

interface ScanStatusBadgeProps {
  status: ScanStatus;
  large?: boolean;
}

const statusStyles: Record<ScanStatus, { text: string; bg: string; dot: string; }> = {
  [ScanStatus.Pending]: { text: 'Pending', bg: 'bg-gray-700', dot: 'bg-gray-400' },
  [ScanStatus.RunningSubfinder]: { text: 'Finding Subdomains', bg: 'bg-blue-900', dot: 'bg-blue-400' },
  [ScanStatus.RunningHttpx]: { text: 'Probing Hosts', bg: 'bg-blue-900', dot: 'bg-blue-400' },
  [ScanStatus.RunningNuclei]: { text: 'Scanning for Vulns', bg: 'bg-yellow-900', dot: 'bg-yellow-400' },
  [ScanStatus.Completed]: { text: 'Completed', bg: 'bg-green-900', dot: 'bg-green-400' },
  [ScanStatus.Failed]: { text: 'Failed', bg: 'bg-red-900', dot: 'bg-red-400' },
};

const ScanStatusBadge: React.FC<ScanStatusBadgeProps> = ({ status, large = false }) => {
  const style = statusStyles[status] || statusStyles[ScanStatus.Pending];
  const isRunning = status.startsWith('running');
  
  const textSize = large ? 'text-base px-4 py-2' : 'text-xs px-2.5 py-1';

  return (
    <span className={`inline-flex items-center gap-x-1.5 rounded-full ${textSize} font-medium text-brand-text ${style.bg}`}>
      <span className={`h-2 w-2 rounded-full ${style.dot} ${isRunning ? 'animate-pulse' : ''}`} />
      {style.text}
    </span>
  );
};

export default ScanStatusBadge;