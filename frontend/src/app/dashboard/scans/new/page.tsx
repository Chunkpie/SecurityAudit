'use client';
import { useState, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { useQuery } from '@tanstack/react-query';
import { Shield, AlertTriangle, Loader2, ChevronDown } from 'lucide-react';
import { toast } from 'sonner';
import { scanApi, orgApi } from '@/lib/api';
import { useAuthStore } from '@/lib/store';
import type { ScanType } from '@/types';

const SCAN_TYPES: { value: ScanType; label: string; desc: string; duration: string }[] = [
  { value: 'full', label: 'Full Audit', desc: 'Comprehensive scan: TLS, headers, exposures, ports, injection, nuclei templates', duration: '5–15 min' },
  { value: 'quick', label: 'Quick Scan', desc: 'Fast check: TLS validity, security headers, and sensitive file exposure', duration: '1–2 min' },
  { value: 'tls', label: 'TLS / SSL Only', desc: 'Deep TLS analysis: protocols, ciphers, certificate chain, HSTS', duration: '1–3 min' },
  { value: 'headers', label: 'Headers Only', desc: 'Security headers, CORS policy, server version disclosure', duration: '< 1 min' },
  { value: 'vulnerabilities', label: 'Vulnerability Scan', desc: 'Nuclei templates, SQLi, XSS, injection vectors', duration: '5–10 min' },
];

export default function NewScanPage() {
  return (
    <Suspense fallback={<div className="p-8 text-gray-400 text-sm">Loading…</div>}>
      <NewScanPageContent />
    </Suspense>
  );
}

function NewScanPageContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { currentOrg } = useAuthStore();

  const [targetUrl, setTargetUrl] = useState('https://');
  const [scanType, setScanType] = useState<ScanType>((searchParams.get('type') as ScanType) || 'full');
  const [consent, setConsent] = useState(false);
  const [enableSchedule, setEnableSchedule] = useState(false);
  const [scheduleFreq, setScheduleFreq] = useState<'daily' | 'weekly' | 'monthly'>('weekly');
  const [loading, setLoading] = useState(false);
  const [enableNuclei, setEnableNuclei] = useState(true);
  const [enableInjection, setEnableInjection] = useState(true);

  const { data: orgs } = useQuery({
    queryKey: ['organizations'],
    queryFn: () => orgApi.list().then((r) => r.data),
  });

  const orgId = currentOrg?.id || orgs?.[0]?.id;

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!consent) { toast.error('You must confirm authorization to scan this target.'); return; }
    if (!orgId) { toast.error('Please create an organization first.'); return; }
    if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
      toast.error('URL must start with http:// or https://'); return;
    }

    setLoading(true);
    try {
      const { data: scan } = await scanApi.create({
        target_url: targetUrl,
        scan_type: scanType,
        organization_id: orgId,
        consent_confirmed: true,
        scheduled: enableSchedule,
        schedule_frequency: enableSchedule ? scheduleFreq : undefined,
        scan_config: { enable_nuclei: enableNuclei, enable_injection: enableInjection },
      });
      toast.success('Scan started!');
      router.push(`/dashboard/scans/${scan.id}`);
    } catch (err: any) {
      toast.error(err?.response?.data?.detail || 'Failed to start scan');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="p-8 max-w-3xl">
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-gray-900">New Security Scan</h1>
        <p className="text-gray-500 text-sm mt-1">Configure and launch a security audit</p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Target URL */}
        <div className="bg-white border border-gray-200 rounded-xl p-5">
          <label className="block text-sm font-semibold text-gray-800 mb-3">Target URL</label>
          <input
            type="url" required value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            className="w-full px-3.5 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none text-sm font-mono"
            placeholder="https://example.com"
          />
          <p className="text-xs text-gray-400 mt-2">
            Include the full URL with protocol. Subdomains will be discovered automatically.
          </p>
        </div>

        {/* Scan Type */}
        <div className="bg-white border border-gray-200 rounded-xl p-5">
          <label className="block text-sm font-semibold text-gray-800 mb-3">Scan Type</label>
          <div className="space-y-2">
            {SCAN_TYPES.map((type) => (
              <label
                key={type.value}
                className={`flex items-start gap-3 p-3.5 border rounded-lg cursor-pointer transition-colors ${
                  scanType === type.value
                    ? 'border-blue-500 bg-blue-50'
                    : 'border-gray-200 hover:border-gray-300 hover:bg-gray-50'
                }`}
              >
                <input
                  type="radio" name="scanType" value={type.value}
                  checked={scanType === type.value}
                  onChange={() => setScanType(type.value)}
                  className="mt-0.5 accent-blue-600"
                />
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-gray-800">{type.label}</span>
                    <span className="text-xs text-gray-400 bg-gray-100 px-2 py-0.5 rounded-full">{type.duration}</span>
                  </div>
                  <p className="text-xs text-gray-500 mt-0.5">{type.desc}</p>
                </div>
              </label>
            ))}
          </div>
        </div>

        {/* Advanced Options */}
        {(scanType === 'full' || scanType === 'vulnerabilities') && (
          <div className="bg-white border border-gray-200 rounded-xl p-5">
            <label className="block text-sm font-semibold text-gray-800 mb-3">Scan Options</label>
            <div className="space-y-3">
              <label className="flex items-center gap-3 cursor-pointer">
                <input type="checkbox" checked={enableNuclei}
                  onChange={(e) => setEnableNuclei(e.target.checked)}
                  className="w-4 h-4 accent-blue-600 rounded" />
                <div>
                  <span className="text-sm font-medium text-gray-700">Nuclei Templates</span>
                  <p className="text-xs text-gray-400">Run community vulnerability templates (CVEs, misconfigs)</p>
                </div>
              </label>
              <label className="flex items-center gap-3 cursor-pointer">
                <input type="checkbox" checked={enableInjection}
                  onChange={(e) => setEnableInjection(e.target.checked)}
                  className="w-4 h-4 accent-blue-600 rounded" />
                <div>
                  <span className="text-sm font-medium text-gray-700">Injection Testing</span>
                  <p className="text-xs text-gray-400">SQLMap-based SQL injection detection (safe mode, no destructive tests)</p>
                </div>
              </label>
            </div>
          </div>
        )}

        {/* Scheduled Scans */}
        <div className="bg-white border border-gray-200 rounded-xl p-5">
          <div className="flex items-center justify-between mb-3">
            <label className="text-sm font-semibold text-gray-800">Scheduled Scanning</label>
            <label className="relative inline-flex items-center cursor-pointer">
              <input type="checkbox" checked={enableSchedule}
                onChange={(e) => setEnableSchedule(e.target.checked)}
                className="sr-only peer" />
              <div className="w-10 h-5 bg-gray-200 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-0.5 after:left-0.5 after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-blue-600" />
            </label>
          </div>
          {enableSchedule && (
            <div className="flex gap-2">
              {(['daily', 'weekly', 'monthly'] as const).map((f) => (
                <button key={f} type="button"
                  onClick={() => setScheduleFreq(f)}
                  className={`px-4 py-1.5 rounded-full text-sm font-medium border transition-colors ${
                    scheduleFreq === f ? 'bg-blue-600 text-white border-blue-600' : 'text-gray-600 border-gray-300 hover:border-blue-400'
                  }`}>
                  {f.charAt(0).toUpperCase() + f.slice(1)}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Authorization Consent */}
        <div className={`border rounded-xl p-5 transition-colors ${consent ? 'bg-green-50 border-green-300' : 'bg-amber-50 border-amber-300'}`}>
          <div className="flex gap-3">
            <AlertTriangle className={`w-5 h-5 mt-0.5 shrink-0 ${consent ? 'text-green-600' : 'text-amber-600'}`} />
            <div>
              <p className="text-sm font-semibold text-gray-800 mb-2">Authorization Required</p>
              <p className="text-sm text-gray-600 mb-3 leading-relaxed">
                By starting this scan, you confirm that you <strong>own</strong> the target asset
                or have <strong>explicit written authorization</strong> to perform security testing on it.
                Unauthorized scanning may violate local laws and terms of service.
                Your consent, IP address, and timestamp will be recorded.
              </p>
              <label className="flex items-center gap-2.5 cursor-pointer">
                <input
                  type="checkbox" checked={consent}
                  onChange={(e) => setConsent(e.target.checked)}
                  className="w-4 h-4 accent-green-600 rounded"
                />
                <span className="text-sm font-medium text-gray-700">
                  I confirm I own or am authorized to test <code className="bg-gray-100 px-1 rounded text-xs">{targetUrl || 'this target'}</code>
                </span>
              </label>
            </div>
          </div>
        </div>

        <button
          type="submit" disabled={loading || !consent}
          className="w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold py-3 rounded-xl transition-colors flex items-center justify-center gap-2"
        >
          {loading ? (
            <><Loader2 className="w-4 h-4 animate-spin" /> Starting Scan…</>
          ) : (
            <><Shield className="w-4 h-4" /> Launch Security Scan</>
          )}
        </button>
      </form>
    </div>
  );
}
