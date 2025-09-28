
import React from 'react';
import { Severity } from '../types';

interface SeverityBadgeProps {
  severity: Severity;
}

const severityStyles: Record<Severity, { text: string; className: string; }> = {
  [Severity.Critical]: { text: 'Critical', className: 'bg-severity-critical text-white' },
  [Severity.High]: { text: 'High', className: 'bg-severity-high text-white' },
  [Severity.Medium]: { text: 'Medium', className: 'bg-severity-medium text-black' },
  [Severity.Low]: { text: 'Low', className: 'bg-severity-low text-white' },
  [Severity.Info]: { text: 'Info', className: 'bg-severity-info text-white' },
  [Severity.Unknown]: { text: 'Unknown', className: 'bg-gray-500 text-white' },
};

const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity }) => {
  const style = severityStyles[severity] || severityStyles[Severity.Unknown];
  
  return (
    <span className={`inline-block whitespace-nowrap rounded-md px-2 py-1 text-xs font-bold ${style.className}`}>
      {style.text}
    </span>
  );
};

export default SeverityBadge;