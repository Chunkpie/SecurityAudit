'use client';
import { useState } from 'react';
import { useAuthStore } from '@/lib/store';
import { User, Key, Bell, Shield } from 'lucide-react';
import { toast } from 'sonner';

export default function SettingsPage() {
  const { user } = useAuthStore();
  const [activeTab, setActiveTab] = useState('profile');

  const tabs = [
    { id: 'profile', label: 'Profile', icon: User },
    { id: 'api', label: 'API Keys', icon: Key },
    { id: 'notifications', label: 'Notifications', icon: Bell },
    { id: 'security', label: 'Security', icon: Shield },
  ];

  return (
    <div className="p-8">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Settings</h1>
        <p className="text-gray-500 text-sm mt-1">Manage your account and preferences</p>
      </div>

      <div className="flex gap-6">
        {/* Sidebar tabs */}
        <div className="w-48 shrink-0">
          <nav className="space-y-1">
            {tabs.map(({ id, label, icon: Icon }) => (
              <button key={id} onClick={() => setActiveTab(id)}
                className={`flex items-center gap-2.5 w-full px-3 py-2.5 rounded-lg text-sm font-medium transition-colors text-left ${
                  activeTab === id ? 'bg-blue-50 text-blue-700' : 'text-gray-600 hover:bg-gray-100'
                }`}>
                <Icon className="w-4 h-4" /> {label}
              </button>
            ))}
          </nav>
        </div>

        {/* Content */}
        <div className="flex-1 bg-white border border-gray-200 rounded-xl p-6">
          {activeTab === 'profile' && (
            <div>
              <h2 className="text-base font-semibold text-gray-800 mb-5">Profile Information</h2>
              <div className="space-y-4 max-w-md">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1.5">Full Name</label>
                  <input defaultValue={user?.full_name}
                    className="w-full px-3.5 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 outline-none text-sm" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1.5">Email</label>
                  <input defaultValue={user?.email} type="email"
                    className="w-full px-3.5 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 outline-none text-sm" />
                </div>
                <button onClick={() => toast.success('Profile updated')}
                  className="bg-blue-600 hover:bg-blue-700 text-white px-5 py-2.5 rounded-lg text-sm font-medium transition-colors">
                  Save Changes
                </button>
              </div>
            </div>
          )}

          {activeTab === 'api' && (
            <div>
              <h2 className="text-base font-semibold text-gray-800 mb-2">API Keys</h2>
              <p className="text-sm text-gray-500 mb-5">
                Use API keys to authenticate requests from CI/CD pipelines and external tools.
              </p>
              <div className="bg-gray-50 border border-dashed border-gray-300 rounded-xl p-8 text-center">
                <Key className="w-8 h-8 text-gray-400 mx-auto mb-3" />
                <p className="text-gray-500 text-sm">No API keys yet</p>
                <button
                  onClick={() => toast.info('API key creation coming soon')}
                  className="mt-3 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors">
                  Create API Key
                </button>
              </div>
            </div>
          )}

          {activeTab === 'notifications' && (
            <div>
              <h2 className="text-base font-semibold text-gray-800 mb-5">Notification Preferences</h2>
              <div className="space-y-4">
                {[
                  { label: 'Scan completed', desc: 'Get notified when a scan finishes' },
                  { label: 'Critical findings', desc: 'Alert on critical severity vulnerabilities' },
                  { label: 'Scheduled scan results', desc: 'Weekly digest of scheduled scans' },
                ].map((item) => (
                  <label key={item.label} className="flex items-center justify-between py-3 border-b border-gray-100 last:border-0 cursor-pointer">
                    <div>
                      <p className="text-sm font-medium text-gray-700">{item.label}</p>
                      <p className="text-xs text-gray-400">{item.desc}</p>
                    </div>
                    <input type="checkbox" defaultChecked className="w-4 h-4 accent-blue-600" />
                  </label>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'security' && (
            <div>
              <h2 className="text-base font-semibold text-gray-800 mb-5">Security Settings</h2>
              <div className="max-w-md space-y-5">
                <div>
                  <h3 className="text-sm font-medium text-gray-700 mb-3">Change Password</h3>
                  <div className="space-y-3">
                    <input type="password" placeholder="Current password"
                      className="w-full px-3.5 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 outline-none text-sm" />
                    <input type="password" placeholder="New password"
                      className="w-full px-3.5 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 outline-none text-sm" />
                    <input type="password" placeholder="Confirm new password"
                      className="w-full px-3.5 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 outline-none text-sm" />
                    <button onClick={() => toast.success('Password updated')}
                      className="bg-blue-600 hover:bg-blue-700 text-white px-5 py-2.5 rounded-lg text-sm font-medium transition-colors">
                      Update Password
                    </button>
                  </div>
                </div>
                <div className="pt-4 border-t border-gray-100">
                  <h3 className="text-sm font-medium text-gray-700 mb-2">Active Sessions</h3>
                  <p className="text-xs text-gray-500">Current session • {new Date().toLocaleDateString()}</p>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
