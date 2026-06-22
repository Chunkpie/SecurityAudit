'use client';
import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Building2, Plus, Users, Loader2, X } from 'lucide-react';
import { toast } from 'sonner';
import { orgApi } from '@/lib/api';
import { useAuthStore } from '@/lib/store';
import { generateSlug } from '@/lib/utils';

export default function OrganizationsPage() {
  const { setCurrentOrg, currentOrg } = useAuthStore();
  const queryClient = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [name, setName] = useState('');
  const [slug, setSlug] = useState('');
  const [description, setDescription] = useState('');

  const { data: orgs, isLoading } = useQuery({
    queryKey: ['organizations'],
    queryFn: () => orgApi.list().then((r) => r.data),
  });

  const createMutation = useMutation({
    mutationFn: () => orgApi.create({ name, slug, description }),
    onSuccess: (res) => {
      queryClient.invalidateQueries({ queryKey: ['organizations'] });
      setCurrentOrg(res.data);
      toast.success('Organization created');
      setShowCreate(false);
      setName(''); setSlug(''); setDescription('');
    },
    onError: (err: any) => toast.error(err?.response?.data?.detail || 'Failed to create'),
  });

  return (
    <div className="p-8">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Organizations</h1>
          <p className="text-gray-500 text-sm mt-1">Manage your teams and workspaces</p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2.5 rounded-lg text-sm font-medium transition-colors"
        >
          <Plus className="w-4 h-4" /> New Organization
        </button>
      </div>

      {isLoading ? (
        <div className="text-center py-10 text-gray-400">Loading…</div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {orgs?.map((org: any) => (
            <div
              key={org.id}
              onClick={() => { setCurrentOrg(org); toast.success(`Switched to ${org.name}`); }}
              className={`bg-white border rounded-xl p-5 cursor-pointer transition-colors hover:border-blue-300 ${
                currentOrg?.id === org.id ? 'border-blue-500 ring-1 ring-blue-500' : 'border-gray-200'
              }`}
            >
              <div className="flex items-start gap-3">
                <div className="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center shrink-0">
                  <Building2 className="w-5 h-5 text-blue-600" />
                </div>
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <h3 className="font-semibold text-gray-800">{org.name}</h3>
                    {currentOrg?.id === org.id && (
                      <span className="text-xs bg-blue-100 text-blue-700 px-2 py-0.5 rounded-full">Active</span>
                    )}
                  </div>
                  <p className="text-xs text-gray-400 mt-0.5">/{org.slug}</p>
                  {org.description && <p className="text-sm text-gray-500 mt-2">{org.description}</p>}
                  <div className="flex items-center gap-2 mt-3">
                    <span className="text-xs bg-gray-100 text-gray-600 px-2 py-0.5 rounded-full capitalize">{org.plan} plan</span>
                  </div>
                </div>
              </div>
            </div>
          ))}
          {!orgs?.length && (
            <div className="col-span-2 text-center py-12 bg-white border border-gray-200 rounded-xl">
              <Building2 className="w-10 h-10 text-gray-300 mx-auto mb-3" />
              <p className="text-gray-500">No organizations yet. Create your first one.</p>
            </div>
          )}
        </div>
      )}

      {/* Create Modal */}
      {showCreate && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-2xl w-full max-w-md shadow-2xl">
            <div className="flex items-center justify-between px-6 py-4 border-b border-gray-100">
              <h2 className="text-lg font-semibold text-gray-900">New Organization</h2>
              <button onClick={() => setShowCreate(false)} className="text-gray-400 hover:text-gray-600">
                <X className="w-5 h-5" />
              </button>
            </div>
            <form onSubmit={(e) => { e.preventDefault(); createMutation.mutate(); }} className="p-6 space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1.5">Organization Name</label>
                <input
                  required value={name}
                  onChange={(e) => { setName(e.target.value); setSlug(generateSlug(e.target.value)); }}
                  className="w-full px-3.5 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 outline-none text-sm"
                  placeholder="Acme Corp"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1.5">Slug</label>
                <input
                  required value={slug} onChange={(e) => setSlug(e.target.value)}
                  pattern="[a-z0-9\-]+"
                  className="w-full px-3.5 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 outline-none text-sm font-mono"
                  placeholder="acme-corp"
                />
                <p className="text-xs text-gray-400 mt-1">Lowercase letters, numbers, hyphens only</p>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1.5">Description <span className="text-gray-400">(optional)</span></label>
                <textarea
                  value={description} onChange={(e) => setDescription(e.target.value)}
                  rows={2}
                  className="w-full px-3.5 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 outline-none text-sm resize-none"
                  placeholder="Team workspace for security audits"
                />
              </div>
              <div className="flex gap-3 pt-2">
                <button type="button" onClick={() => setShowCreate(false)}
                  className="flex-1 py-2.5 border border-gray-300 rounded-lg text-sm text-gray-700 hover:bg-gray-50 transition-colors">
                  Cancel
                </button>
                <button type="submit" disabled={createMutation.isPending}
                  className="flex-1 bg-blue-600 hover:bg-blue-700 text-white py-2.5 rounded-lg text-sm font-medium transition-colors flex items-center justify-center gap-2 disabled:opacity-60">
                  {createMutation.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
                  Create
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
