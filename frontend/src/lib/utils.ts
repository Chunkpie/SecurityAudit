import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import type { FindingSeverity, DeploymentVerdict, ScanStatus } from '@/types';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function severityColor(severity: FindingSeverity): string {
  const colors: Record<FindingSeverity, string> = {
    critical: 'bg-red-100 text-red-800 border-red-200',
    high: 'bg-orange-100 text-orange-800 border-orange-200',
    medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
    low: 'bg-blue-100 text-blue-800 border-blue-200',
    info: 'bg-gray-100 text-gray-700 border-gray-200',
  };
  return colors[severity] || colors.info;
}

export function severityDotColor(severity: FindingSeverity): string {
  const colors: Record<FindingSeverity, string> = {
    critical: 'bg-red-500',
    high: 'bg-orange-500',
    medium: 'bg-yellow-500',
    low: 'bg-blue-500',
    info: 'bg-gray-400',
  };
  return colors[severity] || 'bg-gray-400';
}

export function verdictColor(verdict: DeploymentVerdict): string {
  const colors: Record<DeploymentVerdict, string> = {
    GO: 'bg-green-100 text-green-800 border-green-300',
    GO_WITH_CONDITIONS: 'bg-yellow-100 text-yellow-800 border-yellow-300',
    NO_GO: 'bg-red-100 text-red-800 border-red-300',
  };
  return colors[verdict] || 'bg-gray-100 text-gray-700';
}

export function verdictLabel(verdict: DeploymentVerdict): string {
  return { GO: '✓ GO', GO_WITH_CONDITIONS: '⚠ GO WITH CONDITIONS', NO_GO: '✗ NO-GO' }[verdict] || verdict;
}

export function scoreColor(score: number): string {
  if (score >= 80) return 'text-green-600';
  if (score >= 60) return 'text-yellow-600';
  return 'text-red-600';
}

export function scoreBg(score: number): string {
  if (score >= 80) return 'bg-green-500';
  if (score >= 60) return 'bg-yellow-500';
  return 'bg-red-500';
}

export function statusColor(status: ScanStatus): string {
  const colors: Record<ScanStatus, string> = {
    pending: 'bg-gray-100 text-gray-600',
    queued: 'bg-blue-100 text-blue-600',
    running: 'bg-indigo-100 text-indigo-600',
    completed: 'bg-green-100 text-green-700',
    failed: 'bg-red-100 text-red-700',
    cancelled: 'bg-gray-100 text-gray-500',
  };
  return colors[status] || 'bg-gray-100 text-gray-600';
}

export function formatDate(dateStr: string | undefined): string {
  if (!dateStr) return '—';
  return new Date(dateStr).toLocaleDateString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

export function formatDuration(start?: string, end?: string): string {
  if (!start || !end) return '—';
  const ms = new Date(end).getTime() - new Date(start).getTime();
  const secs = Math.floor(ms / 1000);
  if (secs < 60) return `${secs}s`;
  const mins = Math.floor(secs / 60);
  return `${mins}m ${secs % 60}s`;
}

export function generateSlug(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}
