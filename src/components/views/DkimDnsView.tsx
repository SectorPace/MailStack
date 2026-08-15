import React, { useState } from 'react';
import { useApp } from '../../context/AppContext';
import { KeyRound, ShieldCheck, Copy, CheckCircle2, RefreshCw, Globe, Check, Layers, ExternalLink } from 'lucide-react';
import confetti from 'canvas-confetti';
import { DnsGuideTable } from '../dns/DnsGuideTable';

export const DkimDnsView: React.FC = () => {
  const { domains, language, themeMode, showToast } = useApp();
  const [selectedDomainId, setSelectedDomainId] = useState(domains[0]?.id || '');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [isRotating, setIsRotating] = useState(false);

  const selectedDomain = domains.find(d => d.id === selectedDomainId) || domains[0];

  const dkimHost = `${selectedDomain?.dkimSelector || 's20260809795'}._domainkey.${selectedDomain?.name || 'sectorpace.com'}`;
  const dkimPublicKeyRaw = `MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAru0is9YcUzb8evu7ljUx2dKJw/rpNHp0OXe14Eu4FFkwNZHlpjo9wK93FD0/yc99lLVgJbDCmp8PaHO3obPzUGkHuVec5BtWxYMzNrT3A3WWqXFB+Uex8Ly0UfW8MMfkzki5fypEAcQcH9MK8sZKiFTvChrOtINae7owf8sUAYMqy75X8FMmPoErRxJ5y6CfsYbTjmfmUw...DAQAB`;
  const dkimFullTxtValue = `v=DKIM1; k=rsa; p=${dkimPublicKeyRaw}`;

  const spfRecord = `v=spf1 mx include:spf.us-sanjose-1.oci.oraclecloud.com ~all`;
  const dmarcRecord = `v=DMARC1; p=none; rua=mailto:admin@${selectedDomain?.name || 'sectorpace.com'}; ruf=mailto:admin@${selectedDomain?.name || 'sectorpace.com'}; fo=1; aspf=r; adkim=r`;

  const copyToClipboard = (text: string, label: string, keyId: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(keyId);
    showToast('info', language === 'zh' ? '已复制到剪贴板' : 'Copied to Clipboard', `${label}: ${text.substring(0, 32)}...`);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleRotateKey = () => {
    setIsRotating(true);
    setTimeout(() => {
      setIsRotating(false);
      confetti({ particleCount: 35, spread: 60 });
      showToast('success', language === 'zh' ? 'DKIM 密钥已轮换' : 'DKIM Key Rotated', `${selectedDomain?.name} ${language === 'zh' ? '已生成 2048-bit RSA 新公私钥对' : '2048-bit RSA keypair regenerated'}`);
    }, 1200);
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto font-sans">
      {/* Interactive Full DNS & Relay Table (1:1 with Screenshot & Cloudflare specs) */}
      <DnsGuideTable domain={selectedDomain} serverIp="163.192.27.230" relayProvider="oracle" />
    </div>
  );
};
