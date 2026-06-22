'use client';
import { useQuery } from '@tanstack/react-query';
import { scanApi, orgApi } from '@/lib/api';
import { useAuthStore } from '@/lib/store';
import { Shield, Search, AlertTriangle, TrendingUp, Clock, CheckCircle, XCircle, AlertCircle } from 'lucide-react';
import Link from 'next/link';
import { formatDate, scoreColor, verdictColor, verdictLabel, statusColor } from '@/lib/utils';
import type { Scan } from '@/types';
import { useEffect } from 'react';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer
} from 'recharts';

export default function DashboardPage() {
  const { currentOrg, setOrganizations, setCurrentOrg, organizations } = useAuthStore();

  const { data: orgs } = useQuery({
    queryKey: ['organizations'],
    queryFn: () => orgApi.list().then((r) => r.data),
  });

  useEffect(() => {
    if (orgs?.length) {
      setOrganizations(orgs);
      if (!currentOrg) setCurrentOrg(orgs[0]);
    }
  }, [orgs]);

  const { data: scansData, isLoading } = useQuery({
    queryKey: ['scans', currentOrg?.id],
    queryFn: () => scanApi.list(currentOrg!.id).then((r) => r.data),
    enabled: !!currentOrg,
  });

  const scans: Scan[] = scansData?.items || [];
  const completed = scans.filter((s) => s.status === 'completed');
  const running = scans.filter((s) => ['running', 'queued', 'pending'].includes(s.status));
  const avgScore = completed.length
    ? Math.round(completed.reduce((a, s) => a + (s.security_score || 0), 0) / completed.length)
    : 0;

  const scoreHistory = completed.slice(0, 10).reverse().map((s, i) => ({
    name: `#${i + 1}`,
    score: s.security_score || 0,
    domain: s.target_domain,
  }));

  if (!currentOrg && !isLoading) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-4 text-center p-8">
        <Shield className="w-16 h-16 text-gray-300" />
        <h2 className="text-xl font-semibold text-gray-700">No organization yet</h2>
        <p className="text-gray-500">Create an organization to start scanning.</p>
        <Link href="/dashboard/organizations" className="bg-blue-600 text-white px-6 py-2.5 rounded-lg font-medium hover:bg-blue-700 transition-colors">
          Create Organization
        </Link>
      </div>
    );
  }

  return (
    <div className="p-8">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
          <p className="text-gray-500 text-sm mt-1">{currentOrg?.name}</p>
        </div>
        <Link
          href="/dashboard/scans/new"
          className="inline-flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white px-5 py-2.5 rounded-lg font-medium text-sm transition-colors"
        >
          <Search className="w-4 h-4" /> New Scan
        </Link>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-5 mb-8">
        <StatCard icon={Search} label="Total Scans" value={scans.length} color="blue" />
        <StatCard icon={Clock} label="Active Scans" value={running.length} color="indigo" pulse={running.length > 0} />
        <StatCard icon={TrendingUp} label="Avg Score" value={`${avgScore}/100`} color={avgScore >= 80 ? 'green' : avgScore >= 60 ? 'yellow' : 'red'} />
        <StatCard icon={CheckCircle} label="Completed" value={completed.length} color="green" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        {/* Score trend chart */}
        {scoreHistory.length > 1 && (
          <div className="lg:col-span-2 bg-white border border-gray-200 rounded-xl p-5">
            <h2 className="text-sm font-semibold text-gray-700 mb-4">Security Score Trend</h2>
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={scoreHistory}>
                <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
                <XAxis dataKey="name" tick={{ fontSize: 12 }} />
                <YAxis domain={[0, 100]} tick={{ fontSize: 12 }} />
                <Tooltip
                  contentStyle={{ fontSize: 12, borderRadius: 8 }}
                  formatter={(v: number) => [`${v}/100`, 'Score']}
                />
                <Line type="monotone" dataKey="score" stroke="#3b82f6" strokeWidth={2} dot={{ r: 4 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        )}

        {/* Quick actions */}
        <div className="bg-white border border-gray-200 rounded-xl p-5">
          <h2 className="text-sm font-semibold text-gray-700 mb-4">Quick Actions</h2>
          <div className="space-y-2">
            {[
              { href: '/dashboard/scans/new', label: 'Run Full Audit', desc: 'Comprehensive security scan', color: 'bg-blue-50 border-blue-200 hover:bg-blue-100' },
              { href: '/dashboard/scans/new?type=quick', label: 'Quick Scan', desc: 'Headers & TLS only', color: 'bg-green-50 border-green-200 hover:bg-green-100' },
              { href: '/dashboard/findings', label: 'View Findings', desc: 'Review all vulnerabilities', color: 'bg-orange-50 border-orange-200 hover:bg-orange-100' },
            ].map((a) => (
              <Link key={a.href} href={a.href}
                className={`block border rounded-lg px-4 py-3 transition-colors ${a.color}`}>
                <p className="text-sm font-medium text-gray-800">{a.label}</p>
                <p className="text-xs text-gray-500">{a.desc}</p>
              </Link>
            ))}
          </div>
        </div>
      </div>

      {/* Recent scans table */}
      <div className="bg-white border border-gray-200 rounded-xl">
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-100">
          <h2 className="text-sm font-semibold text-gray-700">Recent Scans</h2>
          <Link href="/dashboard/scans" className="text-xs text-blue-600 hover:underline">View all</Link>
        </div>
        {isLoading ? (
          <div className="p-8 text-center text-gray-400 text-sm">Loading…</div>
        ) : scans.length === 0 ? (
          <div className="p-10 text-center">
            <Shield className="w-10 h-10 text-gray-300 mx-auto mb-3" />
            <p className="text-gray-500 text-sm">No scans yet. Start your first audit!</p>
            <Link href="/dashboard/scans/new"
              className="mt-4 inline-block bg-blue-600 text-white px-5 py-2 rounded-lg text-sm font-medium hover:bg-blue-700 transition-colors">
              Start Scan
            </Link>
          </div>
        ) : (
          <div className="divide-y divide-gray-50">
            {scans.slice(0, 8).map((scan) => (
              <Link key={scan.id} href={`/dashboard/scans/${scan.id}`}
                className="flex items-center justify-between px-5 py-3.5 hover:bg-gray-50 transition-colors">
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 bg-blue-50 rounded-lg flex items-center justify-center">
                    <Shield className="w-4 h-4 text-blue-500" />
                  </div>
                  <div>
                    <p className="text-sm font-medium text-gray-800">{scan.target_domain}</p>
                    <p className="text-xs text-gray-400">{formatDate(scan.created_at)}</p>
                  </div>
                </div>
                <div className="flex items-center gap-4">
                  {scan.security_score !== undefined && scan.security_score !== null && (
                    <span className={`text-sm font-bold ${scoreColor(scan.security_score)}`}>
                      {scan.security_score}/100
                    </span>
                  )}
                  {scan.verdict && (
                    <span className={`text-xs font-semibold px-2.5 py-1 rounded-full border ${verdictColor(scan.verdict as any)}`}>
                      {scan.verdict === 'GO' ? '✓ GO' : scan.verdict === 'GO_WITH_CONDITIONS' ? '⚠ COND' : '✗ NO-GO'}
                    </span>
                  )}
                  <span className={`text-xs px-2 py-0.5 rounded-full ${statusColor(scan.status as any)}`}>
                    {scan.status}
                  </span>
                </div>
              </Link>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function StatCard({ icon: Icon, label, value, color, pulse }: {
  icon: any; label: string; value: string | number; color: string; pulse?: boolean;
}) {
  const colorMap: Record<string, string> = {
    blue: 'bg-blue-50 text-blue-600',
    indigo: 'bg-indigo-50 text-indigo-600',
    green: 'bg-green-50 text-green-600',
    yellow: 'bg-yellow-50 text-yellow-600',
    red: 'bg-red-50 text-red-600',
  };
  return (
    <div className="bg-white border border-gray-200 rounded-xl p-5">
      <div className={`w-10 h-10 rounded-lg flex items-center justify-center mb-3 ${colorMap[color] || colorMap.blue} ${pulse ? 'animate-pulse' : ''}`}>
        <Icon className="w-5 h-5" />
      </div>
      <div className="text-2xl font-bold text-gray-900">{value}</div>
      <div className="text-xs text-gray-500 mt-0.5">{label}</div>
    </div>
  );
}
