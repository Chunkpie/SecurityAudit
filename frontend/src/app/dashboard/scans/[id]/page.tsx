'use client';
import { useEffect } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Shield, Clock, CheckCircle, XCircle, AlertTriangle, Download,
  RefreshCw, StopCircle, ExternalLink, ChevronRight
} from 'lucide-react';
import { toast } from 'sonner';
import { scanApi, findingsApi, reportApi, downloadBlob } from '@/lib/api';
import {
  scoreColor, scoreBg, verdictColor, verdictLabel, statusColor,
  severityColor, formatDate, formatDuration, cn
} from '@/lib/utils';
import type { Finding, ScanStatus, DeploymentVerdict } from '@/types';
import { useScanSocket } from '@/lib/useScanSocket';
import Link from 'next/link';
import { RadialBarChart, RadialBar, PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts';

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#dc2626', high: '#ea580c', medium: '#d97706', low: '#2563eb', info: '#6b7280',
};

export default function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const queryClient = useQueryClient();

  const { data: scan, isLoading: scanLoading } = useQuery({
    queryKey: ['scan', id],
    queryFn: () => scanApi.get(id).then((r) => r.data),
    refetchInterval: (q) => {
      const status = q.state.data?.status;
      return ['pending', 'queued', 'running'].includes(status) ? 3000 : false;
    },
  });

  const { data: summary } = useQuery({
    queryKey: ['scan-summary', id],
    queryFn: () => scanApi.summary(id).then((r) => r.data),
    enabled: scan?.status === 'completed',
    refetchInterval: false,
  });

  const { data: findingsData } = useQuery({
    queryKey: ['findings', id],
    queryFn: () => findingsApi.list(id).then((r) => r.data),
    enabled: scan?.status === 'completed',
  });

  const isRunning = ['pending', 'queued', 'running'].includes(scan?.status || '');
  const isComplete = scan?.status === 'completed';
  const findings: Finding[] = findingsData?.items || [];
  const { logs, connected: wsConnected } = useScanSocket(isRunning ? id : undefined);

  const pieData = summary
    ? [
        { name: 'Critical', value: summary.findings_summary.critical, color: SEVERITY_COLORS.critical },
        { name: 'High', value: summary.findings_summary.high, color: SEVERITY_COLORS.high },
        { name: 'Medium', value: summary.findings_summary.medium, color: SEVERITY_COLORS.medium },
        { name: 'Low', value: summary.findings_summary.low, color: SEVERITY_COLORS.low },
        { name: 'Info', value: summary.findings_summary.info, color: SEVERITY_COLORS.info },
      ].filter((d) => d.value > 0)
    : [];

  async function handleStop() {
    try {
      await scanApi.stop(id);
      queryClient.invalidateQueries({ queryKey: ['scan', id] });
      toast.success('Scan cancelled');
    } catch { toast.error('Failed to cancel scan'); }
  }

  async function downloadReport(type: 'pdf' | 'json' | 'csv') {
    try {
      toast.info(`Generating ${type.toUpperCase()} report…`);
      const { data } = await reportApi[type](id);
      downloadBlob(data, `secaudit-report-${id}.${type}`);
      toast.success(`${type.toUpperCase()} report downloaded`);
    } catch { toast.error('Report generation failed'); }
  }

  if (scanLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-6 h-6 text-gray-400 animate-spin" />
      </div>
    );
  }

  if (!scan) return <div className="p-8 text-gray-500">Scan not found.</div>;

  return (
    <div className="p-8">
      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div>
          <div className="flex items-center gap-2 text-sm text-gray-400 mb-2">
            <Link href="/dashboard/scans" className="hover:text-gray-600">Scans</Link>
            <ChevronRight className="w-3.5 h-3.5" />
            <span className="text-gray-700 font-medium">{scan.target_domain}</span>
          </div>
          <h1 className="text-2xl font-bold text-gray-900 flex items-center gap-2">
            {scan.target_domain}
            <a href={scan.target_url} target="_blank" rel="noopener noreferrer"
              className="text-gray-400 hover:text-blue-500 transition-colors">
              <ExternalLink className="w-4 h-4" />
            </a>
          </h1>
          <div className="flex items-center gap-3 mt-2">
            <span className={`text-xs px-2.5 py-1 rounded-full font-medium ${statusColor(scan.status as ScanStatus)}`}>
              {scan.status}
            </span>
            <span className="text-xs text-gray-400">{scan.scan_type} scan</span>
            <span className="text-xs text-gray-400">
              {formatDate(scan.created_at)}
            </span>
            {isComplete && (
              <span className="text-xs text-gray-400">
                Duration: {formatDuration(scan.started_at, scan.completed_at)}
              </span>
            )}
          </div>
        </div>

        <div className="flex items-center gap-2">
          {isRunning && (
            <button onClick={handleStop}
              className="flex items-center gap-1.5 px-3 py-2 text-sm text-red-600 border border-red-200 rounded-lg hover:bg-red-50 transition-colors">
              <StopCircle className="w-4 h-4" /> Stop
            </button>
          )}
          {isComplete && (
            <div className="flex gap-2">
              {(['pdf', 'json', 'csv'] as const).map((t) => (
                <button key={t} onClick={() => downloadReport(t)}
                  className="flex items-center gap-1.5 px-3 py-2 text-sm text-gray-600 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors">
                  <Download className="w-3.5 h-3.5" /> {t.toUpperCase()}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Running state */}
      {isRunning && (
        <div className="bg-blue-50 border border-blue-200 rounded-xl p-6 mb-6 flex items-center gap-4">
          <div className="w-10 h-10 bg-blue-100 rounded-full flex items-center justify-center">
            <RefreshCw className="w-5 h-5 text-blue-600 animate-spin" />
          </div>
          <div>
            <p className="font-semibold text-blue-800">Scan in progress…</p>
            <p className="text-sm text-blue-600 mt-0.5">
              Running security checks on {scan.target_domain}. This may take several minutes.
            </p>
          </div>
        </div>
      )}

      {/* Live Logs */}
      {isRunning && logs.length > 0 && (
        <div className="bg-black text-green-400 border border-green-800 rounded-xl p-4 mb-6 font-mono text-xs max-h-48 overflow-y-auto">
          <div className="flex items-center gap-2 mb-2 text-green-300 text-xs font-sans">
            <span className={`w-2 h-2 rounded-full ${wsConnected ? 'bg-green-400' : 'bg-yellow-400'}`} />
            Live Scan Logs {wsConnected ? '(connected)' : '(reconnecting...)'}
          </div>
          {logs.map((log, i) => (
            <div key={i} className="opacity-80 hover:opacity-100">
              <span className="text-gray-600 mr-2">[{i + 1}]</span>
              {log}
            </div>
          ))}
        </div>
      )}

      {/* Failed state */}
      {scan.status === 'failed' && (
        <div className="bg-red-50 border border-red-200 rounded-xl p-6 mb-6">
          <p className="font-semibold text-red-800">Scan failed</p>
          {scan.error_message && <p className="text-sm text-red-600 mt-1">{scan.error_message}</p>}
        </div>
      )}

      {/* Results */}
      {isComplete && summary && (
        <>
          {/* Score & Verdict */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-5 mb-6">
            <div className="bg-white border border-gray-200 rounded-xl p-6 text-center">
              <div className={`text-5xl font-black mb-1 ${scoreColor(scan.security_score || 0)}`}>
                {scan.security_score}
              </div>
              <div className="text-gray-500 text-sm">Security Score</div>
              <div className="mt-3 h-2 bg-gray-100 rounded-full overflow-hidden">
                <div className={`h-full rounded-full transition-all ${scoreBg(scan.security_score || 0)}`}
                  style={{ width: `${scan.security_score || 0}%` }} />
              </div>
            </div>

            <div className="bg-white border border-gray-200 rounded-xl p-6 text-center">
              <div className={`inline-block text-xl font-bold px-6 py-3 rounded-full border-2 mb-2 ${verdictColor(scan.verdict as DeploymentVerdict)}`}>
                {scan.verdict === 'GO' ? '✓ GO' : scan.verdict === 'GO_WITH_CONDITIONS' ? '⚠ GO WITH CONDITIONS' : '✗ NO-GO'}
              </div>
              <p className="text-gray-500 text-xs mt-2">Deployment Verdict</p>
            </div>

            <div className="bg-white border border-gray-200 rounded-xl p-5">
              {pieData.length > 0 ? (
                <ResponsiveContainer width="100%" height={140}>
                  <PieChart>
                    <Pie data={pieData} cx="50%" cy="50%" innerRadius={40} outerRadius={60}
                      paddingAngle={2} dataKey="value">
                      {pieData.map((entry, i) => (
                        <Cell key={i} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip formatter={(v, n) => [v, n]} />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex items-center justify-center h-full text-green-500">
                  <CheckCircle className="w-12 h-12" />
                </div>
              )}
              <div className="grid grid-cols-5 gap-1 mt-2">
                {(['critical', 'high', 'medium', 'low', 'info'] as const).map((sev) => (
                  <div key={sev} className="text-center">
                    <div className="font-bold text-sm" style={{ color: SEVERITY_COLORS[sev] }}>
                      {(summary.findings_summary as any)[sev]}
                    </div>
                    <div className="text-xs text-gray-400 capitalize">{sev[0]}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {scan.scan_metadata?.raw_findings_before_correlation && (
            <div className="col-span-3 bg-white border border-gray-200 rounded-xl p-3 text-center text-xs text-gray-500 mb-6">
              Raw findings before correlation: {scan.scan_metadata.raw_findings_before_correlation} |
              Final findings: {findings.length} |
              Reduction: {Math.round((1 - findings.length / (scan.scan_metadata.raw_findings_before_correlation as number)) * 100)}%
            </div>
          )}

          {/* Findings list */}
          <div className="bg-white border border-gray-200 rounded-xl">
            <div className="px-5 py-4 border-b border-gray-100 flex items-center justify-between">
              <h2 className="font-semibold text-gray-800">
                Findings <span className="text-gray-400 font-normal">({findings.length})</span>
              </h2>
              <Link href={`/dashboard/findings?scan_id=${id}`}
                className="text-xs text-blue-600 hover:underline">View all</Link>
            </div>
            {findings.length === 0 ? (
              <div className="p-10 text-center">
                <CheckCircle className="w-10 h-10 text-green-400 mx-auto mb-3" />
                <p className="text-gray-500 text-sm">No significant findings detected!</p>
              </div>
            ) : (
              <div className="divide-y divide-gray-50">
                {findings.slice(0, 20).map((f) => (
                  <div key={f.id} className="px-5 py-3.5 flex items-start gap-3 hover:bg-gray-50">
                    <span className={`text-xs font-bold px-2.5 py-1 rounded-full border shrink-0 mt-0.5 ${severityColor(f.severity)}`}>
                      {f.severity.toUpperCase()}
                    </span>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-gray-800">{f.title}</p>
                      <p className="text-xs text-gray-500 mt-0.5 truncate">{f.description}</p>
                      {f.affected_url && (
                        <p className="text-xs text-blue-500 font-mono mt-1 truncate">{f.affected_url}</p>
                      )}
                      <div className="flex items-center gap-2 mt-1">
                        {f.confidence !== undefined && f.confidence !== null && (
                          <span className={`text-xs px-1.5 py-0.5 rounded ${
                            f.confidence >= 0.7 ? 'bg-green-100 text-green-700' :
                            f.confidence >= 0.4 ? 'bg-yellow-100 text-yellow-700' :
                            'bg-gray-100 text-gray-500'
                          }`}>
                            {(f.confidence * 100).toFixed(0)}% confidence
                          </span>
                        )}
                        {f.correlation_status === 'suspicious' && (
                          <span className="text-xs text-yellow-600 bg-yellow-50 px-1.5 py-0.5 rounded">Suspicious</span>
                        )}
                        {f.correlation_status === 'suppressed' && (
                          <span className="text-xs text-gray-500 bg-gray-100 px-1.5 py-0.5 rounded line-through">Suppressed</span>
                        )}
                      </div>
                    </div>
                    {f.cvss_score && (
                      <span className="text-xs text-gray-400 shrink-0">CVSS: {f.cvss_score}</span>
                    )}
                  </div>
                ))}
                {findings.length > 20 && (
                  <div className="px-5 py-3 text-center">
                    <Link href={`/dashboard/findings?scan_id=${id}`}
                      className="text-sm text-blue-600 hover:underline">
                      View {findings.length - 20} more findings →
                    </Link>
                  </div>
                )}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
