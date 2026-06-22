'use client';
import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { FileText, Download, FileJson, FileSpreadsheet, Loader2 } from 'lucide-react';
import { toast } from 'sonner';
import { scanApi, reportApi, downloadBlob } from '@/lib/api';
import { useAuthStore } from '@/lib/store';
import { formatDate, scoreColor, verdictColor } from '@/lib/utils';

export default function ReportsPage() {
  const { currentOrg } = useAuthStore();
  const [downloading, setDownloading] = useState<string | null>(null);

  const { data } = useQuery({
    queryKey: ['scans', currentOrg?.id, 'completed'],
    queryFn: () =>
      scanApi.list(currentOrg!.id, 1, 'completed').then((r) => r.data),
    enabled: !!currentOrg,
  });

  const scans = data?.items || [];

  async function handleDownload(scanId: string, type: 'pdf' | 'json' | 'csv') {
    setDownloading(`${scanId}-${type}`);
    try {
      const { data: blob } = await reportApi[type](scanId);
      const ext = type;
      downloadBlob(blob, `secaudit-${type}-${scanId.slice(0, 8)}.${ext}`);
      toast.success(`${type.toUpperCase()} downloaded`);
    } catch {
      toast.error('Download failed. Try again.');
    } finally {
      setDownloading(null);
    }
  }

  return (
    <div className="p-8">
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-gray-900">Reports</h1>
        <p className="text-gray-500 text-sm mt-1">Download audit reports in PDF, JSON, or CSV format</p>
      </div>

      {scans.length === 0 ? (
        <div className="text-center py-16 bg-white border border-gray-200 rounded-xl">
          <FileText className="w-12 h-12 text-gray-300 mx-auto mb-4" />
          <p className="text-gray-500">No completed scans yet.</p>
          <p className="text-gray-400 text-sm mt-1">Complete a scan to generate downloadable reports.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {scans.map((scan: any) => (
            <div key={scan.id}
              className="bg-white border border-gray-200 rounded-xl px-5 py-4 flex items-center justify-between gap-4">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-3 mb-1">
                  <p className="font-medium text-gray-800 truncate">{scan.target_domain}</p>
                  {scan.verdict && (
                    <span className={`text-xs font-bold px-2.5 py-0.5 rounded-full border ${verdictColor(scan.verdict)}`}>
                      {scan.verdict === 'GO' ? '✓ GO' : scan.verdict === 'GO_WITH_CONDITIONS' ? '⚠ COND' : '✗ NO-GO'}
                    </span>
                  )}
                  {scan.security_score != null && (
                    <span className={`text-sm font-bold ${scoreColor(scan.security_score)}`}>
                      {scan.security_score}/100
                    </span>
                  )}
                </div>
                <p className="text-xs text-gray-400">{formatDate(scan.created_at)} · {scan.scan_type} scan</p>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                {(
                  [
                    { type: 'pdf' as const, icon: FileText, label: 'PDF', color: 'text-red-600 border-red-200 hover:bg-red-50' },
                    { type: 'json' as const, icon: FileJson, label: 'JSON', color: 'text-blue-600 border-blue-200 hover:bg-blue-50' },
                    { type: 'csv' as const, icon: FileSpreadsheet, label: 'CSV', color: 'text-green-600 border-green-200 hover:bg-green-50' },
                  ]
                ).map(({ type, icon: Icon, label, color }) => {
                  const key = `${scan.id}-${type}`;
                  const isLoading = downloading === key;
                  return (
                    <button
                      key={type}
                      onClick={() => handleDownload(scan.id, type)}
                      disabled={!!downloading}
                      className={`flex items-center gap-1.5 px-3 py-1.5 border rounded-lg text-xs font-medium transition-colors disabled:opacity-50 ${color}`}
                    >
                      {isLoading
                        ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        : <Icon className="w-3.5 h-3.5" />
                      }
                      {label}
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Legend */}
      <div className="mt-8 bg-blue-50 border border-blue-100 rounded-xl p-5">
        <h3 className="text-sm font-semibold text-blue-800 mb-2">Report Contents</h3>
        <ul className="text-sm text-blue-700 space-y-1">
          <li><strong>PDF</strong> — Full audit report with cover page, executive summary, findings with evidence, remediation roadmap, and checklist</li>
          <li><strong>JSON</strong> — Machine-readable report for CI/CD integration and custom tooling</li>
          <li><strong>CSV</strong> — Spreadsheet-compatible findings list for tracking and ticketing</li>
        </ul>
      </div>
    </div>
  );
}
