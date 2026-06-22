import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import type { User, Organization } from '@/types';
import { clearAuth } from '@/lib/api';

interface AuthState {
  user: User | null;
  currentOrg: Organization | null;
  organizations: Organization[];
  setUser: (user: User | null) => void;
  setCurrentOrg: (org: Organization | null) => void;
  setOrganizations: (orgs: Organization[]) => void;
  logout: () => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      user: null,
      currentOrg: null,
      organizations: [],
      setUser: (user) => set({ user }),
      setCurrentOrg: (org) => set({ currentOrg: org }),
      setOrganizations: (orgs) => set({ organizations: orgs }),
      logout: () => {
        clearAuth();
        set({ user: null, currentOrg: null, organizations: [] });
      },
    }),
    {
      name: 'secaudit-auth',
      partialize: (state) => ({
        user: state.user,
        currentOrg: state.currentOrg,
      }),
    }
  )
);
