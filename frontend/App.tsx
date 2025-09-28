
import React, { useState, useCallback } from 'react';
import Dashboard from './components/Dashboard';
import ScanDetail from './components/ScanDetail';
import Header from './components/Header';
import type { Scan } from './types';

const App: React.FC = () => {
  const [selectedScan, setSelectedScan] = useState<Scan | null>(null);

  const handleSelectScan = useCallback((scan: Scan) => {
    setSelectedScan(scan);
  }, []);

  const handleBackToDashboard = useCallback(() => {
    setSelectedScan(null);
  }, []);

  return (
    <div className="min-h-screen bg-brand-bg text-brand-text font-sans">
      <Header />
      <main className="p-4 sm:p-6 lg:p-8 max-w-7xl mx-auto">
        {selectedScan ? (
          <ScanDetail scan={selectedScan} onBack={handleBackToDashboard} />
        ) : (
          <Dashboard onSelectScan={handleSelectScan} />
        )}
      </main>
    </div>
  );
};

export default App;