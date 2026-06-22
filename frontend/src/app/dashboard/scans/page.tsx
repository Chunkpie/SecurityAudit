'use client';
import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import Link from 'next/link';
import { Shield, Search, Filter, RefreshCw } from 'lucide-react';
import { scanApi } from '@/lib/api';
import { useAuthStore } from '@/lib/store';
import { scoreColor, verdictColor, statusColor, formatDate, formatDuration } from '@/lib/utils';
import type { ScanStatus } from '@/types';

const STATUSES: { value: string; label: string }[] = [
  { value: '', label: 'All Statuses' },
  { value: 'completed', label: 'Completed' },
  { value: 'running', label: 'Running' },
  { value: 'failed', label: 'Failed' },
  { value: 'cancelled', label: 'Cancelled' },
];

export default function ScansPage() {
  const { currentOrg } = useAuthStore();
  const [page, setPage] = useState(1);
  const [statusFilter, setStatusFilter] = useState('');
  const [search, setSearch] = useState('');

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['scans', currentOrg?.id, page, statusFilter],
    queryFn: () => scanApi.list(currentOrg!.id, page, statusFilter || undefined).then((r) => r.data),
    enabled: !!currentOrg,
    refetchInterval: 10000,
  });

  const scans = data?.items || [];
  const total = data?.total || 0;
  const totalPages = Math.ceil(total / 20);

  const filtered = search
    ? scans.filter((s: any) => s.target_domain.toLowerCase().includes(search.toLowerCase()))
    : scans;

  return (
    <div className="p-8">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Scan History</h1>
          <p className="text-gray-500 text-sm mt-1">{total} total scans</p>
        </div>
        <div className="flex items-center gap-3">
          <button onClick={() => refetch()}
            className="p-2 text-gray-500 hover:text-gray-700 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors">
            <RefreshCw className="w-4 h-4" />
          </button>
          <Link href="/dashboard/scans/new"
            className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-1.5">
            <Shield className="w-4 h-4" /> New Scan
          </Link>
        </div>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3 mb-5">
        <div className="relative flex-1 max-w-xs">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
          <input
            value={search} onChange={(e) => setSearch(e.target.value)}
            placeholder="Search domains…"
            className="w-full pl-9 pr-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none"
          />
        </div>
        <select
          value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}
          className="px-3 py-2 border border-gray-300 rounded-lg text-sm text-gray-700 focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none"
        >
          {STATUSES.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
        </select>
      </div>

      <div className="bg-white border border-gray-200 rounded-xl overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="bg-gray-50 border-b border-gray-100">
              <th className="px-5 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Target</th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Status</th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Score</th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Verdict</th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Type</th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Duration</th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Date</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-50">
            {isLoading ? (
              <tr><td colSpan={7} className="px-5 py-10 text-center text-gray-400 text-sm">Loading…</td></tr>
            ) : filtered.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-5 py-12 text-center">
                  <Shield className="w-10 h-10 text-gray-300 mx-auto mb-3" />
                  <p className="text-gray-500 text-sm">No scans found</p>
                  <Link href="/dashboard/scans/new"
                    className="mt-3 inline-block text-blue-600 text-sm hover:underline">Start your first scan →</Link>
                </td>
              </tr>
            ) : filtered.map((scan: any) => (
              <tr key={scan.id} className="hover:bg-gray-50 transition-colors">
                <td className="px-5 py-3.5">
                  <Link href={`/dashboard/scans/${scan.id}`} className="hover:text-blue-600 transition-colors">
                    <p className="text-sm font-medium text-gray-800">{scan.target_domain}</p>
                    <p className="text-xs text-gray-400 font-mono truncate max-w-xs">{scan.target_url}</p>
                  </Link>
                </td>
                <td className="px-4 py-3.5">
                  <span className={`text-xs px-2.5 py-1 rounded-full font-medium ${statusColor(scan.status)}`}>
                    {scan.status}
                  </span>
                </td>
                <td className="px-4 py-3.5">
                  {scan.security_score != null ? (
                    <span className={`text-sm font-bold ${scoreColor(scan.security_score)}`}>
                      {scan.security_score}/100
                    </span>
                  ) : <span className="text-gray-300">—</span>}
                </td>
                <td className="px-4 py-3.5">
                  {scan.verdict ? (
                    <span className={`text-xs font-semibold px-2.5 py-1 rounded-full border ${verdictColor(scan.verdict)}`}>
                      {scan.verdict === 'GO' ? '✓ GO' : scan.verdict === 'GO_WITH_CONDITIONS' ? '⚠ COND' : '✗ NO-GO'}
                    </span>
                  ) : <span className="text-gray-300 text-sm">—</span>}
                </td>
                <td className="px-4 py-3.5">
                  <span className="text-xs text-gray-500 capitalize">{scan.scan_type}</span>
                </td>
                <td className="px-4 py-3.5">
                  <span className="text-xs text-gray-500">{formatDuration(scan.started_at, scan.completed_at)}</span>
                </td>
                <td className="px-4 py-3.5">
                  <span className="text-xs text-gray-400">{formatDate(scan.created_at)}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {totalPages > 1 && (
          <div className="px-5 py-3 border-t border-gray-100 flex items-center justify-between">
            <span className="text-xs text-gray-500">Page {page} of {totalPages}</span>
            <div className="flex gap-2">
              <button disabled={page === 1} onClick={() => setPage(p => p - 1)}
                className="px-3 py-1 text-xs border border-gray-200 rounded-md hover:bg-gray-50 disabled:opacity-40 transition-colors">
                Previous
              </button>
              <button disabled={page === totalPages} onClick={() => setPage(p => p + 1)}
                className="px-3 py-1 text-xs border border-gray-200 rounded-md hover:bg-gray-50 disabled:opacity-40 transition-colors">
                Next
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
