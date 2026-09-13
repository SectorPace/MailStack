import React, { useState } from 'react';
import { useApp } from '../../context/AppContext';
import { DnsGuideTable } from '../dns/DnsGuideTable';

export const DkimDnsView: React.FC = () => {
  const { domains, settings } = useApp();
  const selectedDomain = domains[0];
  const dynamicHost = typeof window !== 'undefined' ? (window.location.hostname || '127.0.0.1') : '127.0.0.1';

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto font-sans">
      <DnsGuideTable
        domain={selectedDomain}
        serverIp={dynamicHost}
        relayProvider="oracle"
      />
    </div>
  );
};

