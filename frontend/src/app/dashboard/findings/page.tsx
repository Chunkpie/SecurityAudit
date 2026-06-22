'use client';
import { useState, Suspense } from 'react';
import { useSearchParams } from 'next/navigation';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { AlertTriangle, ChevronDown, ChevronRight, CheckCircle, Eye, EyeOff } from 'lucide-react';
import { findingsApi } from '@/lib/api';
import { severityColor, formatDate, cn } from '@/lib/utils';
import type { Finding, FindingSeverity } from '@/types';

const SEVERITIES: FindingSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];

export default function FindingsPage() {
  return (
    <Suspense fallback={<div className="p-8 text-gray-400 text-sm">Loading…</div>}>
      <FindingsPageContent />
    </Suspense>
  );
}

function FindingsPageContent() {
  const searchParams = useSearchParams();
  const scanId = searchParams.get('scan_id') || '';
  const queryClient = useQueryClient();

  const [severityFilter, setSeverityFilter] = useState<FindingSeverity | ''>('');
  const [categoryFilter, setCategoryFilter] = useState('');
  const [showResolved, setShowResolved] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ['findings', scanId, severityFilter, categoryFilter],
    queryFn: () =>
      findingsApi
        .list(scanId, {
          severity: severityFilter || undefined,
          category: categoryFilter || undefined,
          is_resolved: showResolved ? undefined : false,
        })
        .then((r) => r.data),
    enabled: !!scanId,
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, update }: { id: string; update: object }) =>
      findingsApi.update(id, update),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['findings', scanId] }),
  });

  const findings: Finding[] = data?.items || [];
  const categories = [...new Set(findings.map((f) => f.category))].sort();

  if (!scanId) {
    return (
      <div className="p-8 text-center">
        <AlertTriangle className="w-12 h-12 text-gray-300 mx-auto mb-4" />
        <p className="text-gray-500">Select a completed scan to view findings.</p>
      </div>
    );
  }

  return (
    <div className="p-8">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Findings</h1>
        {data && (
          <div className="flex items-center gap-4 mt-2">
            {SEVERITIES.map((sev) => (
              <span key={sev} className={`text-xs font-semibold px-2.5 py-1 rounded-full border ${severityColor(sev)}`}>
                {(data as any)[sev]} {sev}
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3 mb-5">
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value as FindingSeverity | '')}
          className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 outline-none"
        >
          <option value="">All Severities</option>
          {SEVERITIES.map((s) => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
        </select>

        <select
          value={categoryFilter}
          onChange={(e) => setCategoryFilter(e.target.value)}
          className="px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 outline-none"
        >
          <option value="">All Categories</option>
          {categories.map((c) => <option key={c} value={c}>{c}</option>)}
        </select>

        <label className="flex items-center gap-2 text-sm text-gray-600 cursor-pointer">
          <input type="checkbox" checked={showResolved} onChange={(e) => setShowResolved(e.target.checked)}
            className="accent-blue-600 rounded" />
          Show resolved
        </label>
      </div>

      {isLoading ? (
        <div className="text-center py-10 text-gray-400">Loading findings…</div>
      ) : findings.length === 0 ? (
        <div className="text-center py-12 bg-white border border-gray-200 rounded-xl">
          <CheckCircle className="w-10 h-10 text-green-400 mx-auto mb-3" />
          <p className="text-gray-500 text-sm">No findings match your filters.</p>
        </div>
      ) : (
        <div className="space-y-2">
          {findings.map((finding) => (
            <div key={finding.id}
              className={cn('bg-white border rounded-xl overflow-hidden transition-colors',
                finding.is_resolved ? 'opacity-60' : '',
                expanded === finding.id ? 'border-blue-300' : 'border-gray-200'
              )}>
              {/* Finding header */}
              <div
                className="flex items-center gap-3 px-5 py-4 cursor-pointer hover:bg-gray-50 transition-colors"
                onClick={() => setExpanded(expanded === finding.id ? null : finding.id)}
              >
                <span className={`text-xs font-bold px-2.5 py-1 rounded-full border shrink-0 ${severityColor(finding.severity)}`}>
                  {finding.severity.toUpperCase()}
                </span>
                <div className="flex-1 min-w-0">
                  <p className={`text-sm font-medium ${finding.is_resolved ? 'line-through text-gray-400' : 'text-gray-800'}`}>
                    {finding.title}
                  </p>
                  <p className="text-xs text-gray-400 mt-0.5">{finding.category} · {finding.tool_name}</p>
                </div>
                {finding.cvss_score && (
                  <span className="text-xs text-gray-400 shrink-0">CVSS {finding.cvss_score}</span>
                )}
                {finding.is_resolved && (
                  <span className="text-xs text-green-600 font-medium shrink-0">Resolved</span>
                )}
                {expanded === finding.id
                  ? <ChevronDown className="w-4 h-4 text-gray-400 shrink-0" />
                  : <ChevronRight className="w-4 h-4 text-gray-400 shrink-0" />
                }
              </div>

              {/* Expanded detail */}
              {expanded === finding.id && (
                <div className="px-5 pb-5 border-t border-gray-100 pt-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-5 mb-4">
                    <div>
                      <h4 className="text-xs font-semibold text-gray-500 uppercase mb-1.5">Description</h4>
                      <p className="text-sm text-gray-700 leading-relaxed">{finding.description}</p>
                    </div>
                    <div>
                      <h4 className="text-xs font-semibold text-gray-500 uppercase mb-1.5">Impact</h4>
                      <p className="text-sm text-gray-700 leading-relaxed">{finding.impact}</p>
                    </div>
                  </div>

                  {finding.affected_url && (
                    <div className="mb-4">
                      <h4 className="text-xs font-semibold text-gray-500 uppercase mb-1.5">Affected URL</h4>
                      <code className="text-xs bg-gray-100 px-3 py-1.5 rounded font-mono text-blue-700 block break-all">
                        {finding.affected_url}
                      </code>
                    </div>
                  )}

                  {finding.evidence && Object.keys(finding.evidence).length > 0 && (
                    <div className="mb-4">
                      <h4 className="text-xs font-semibold text-gray-500 uppercase mb-1.5">Evidence</h4>
                      <pre className="text-xs bg-slate-900 text-green-400 p-3 rounded-lg overflow-x-auto max-h-40">
                        {JSON.stringify(finding.evidence, null, 2)}
                      </pre>
                    </div>
                  )}

                  <div className="mb-4">
                    <h4 className="text-xs font-semibold text-gray-500 uppercase mb-1.5">Remediation</h4>
                    <div className="bg-green-50 border border-green-200 rounded-lg px-4 py-3">
                      <p className="text-sm text-green-800 leading-relaxed">{finding.remediation}</p>
                    </div>
                  </div>

                  {finding.cve_ids && finding.cve_ids.length > 0 && (
                    <div className="mb-4">
                      <h4 className="text-xs font-semibold text-gray-500 uppercase mb-1.5">CVE References</h4>
                      <div className="flex flex-wrap gap-2">
                        {finding.cve_ids.map((cve) => (
                          <a key={cve}
                            href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                            target="_blank" rel="noopener noreferrer"
                            className="text-xs bg-red-50 text-red-700 border border-red-200 px-2.5 py-1 rounded-full hover:bg-red-100 transition-colors">
                            {cve}
                          </a>
                        ))}
                      </div>
                    </div>
                  )}

                  {finding.verification_steps && (
                    <div className="mb-4">
                      <h4 className="text-xs font-semibold text-gray-500 uppercase mb-1.5">Verification Steps</h4>
                      <pre className="text-xs text-gray-600 whitespace-pre-wrap">{finding.verification_steps}</pre>
                    </div>
                  )}

                  {/* Actions */}
                  <div className="flex items-center gap-2 pt-3 border-t border-gray-100">
                    <button
                      onClick={() => updateMutation.mutate({ id: finding.id, update: { is_resolved: !finding.is_resolved } })}
                      className={cn('flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border transition-colors',
                        finding.is_resolved
                          ? 'text-gray-600 border-gray-200 hover:bg-gray-50'
                          : 'text-green-700 border-green-200 bg-green-50 hover:bg-green-100'
                      )}>
                      <CheckCircle className="w-3.5 h-3.5" />
                      {finding.is_resolved ? 'Mark Unresolved' : 'Mark Resolved'}
                    </button>
                    <button
                      onClick={() => updateMutation.mutate({ id: finding.id, update: { is_false_positive: !finding.is_false_positive } })}
                      className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border border-gray-200 text-gray-600 hover:bg-gray-50 transition-colors">
                      {finding.is_false_positive ? <Eye className="w-3.5 h-3.5" /> : <EyeOff className="w-3.5 h-3.5" />}
                      {finding.is_false_positive ? 'Unflag False Positive' : 'Mark False Positive'}
                    </button>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
