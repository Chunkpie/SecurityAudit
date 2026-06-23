import axios, { AxiosError, InternalAxiosRequestConfig } from 'axios';
import Cookies from 'js-cookie';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || '';

export const api = axios.create({
  baseURL: `${API_BASE}/api/v1`,
  headers: { 'Content-Type': 'application/json' },
  withCredentials: false,
});

// Attach access token
api.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  const token = Cookies.get('access_token');
  if (token && config.headers) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Refresh token on 401
let isRefreshing = false;
let refreshQueue: Array<(token: string) => void> = [];

api.interceptors.response.use(
  (res) => res,
  async (error: AxiosError) => {
    const original = error.config as InternalAxiosRequestConfig & { _retry?: boolean };
    if (error.response?.status === 401 && !original._retry) {
      original._retry = true;
      const refreshToken = Cookies.get('refresh_token');
      if (!refreshToken) {
        clearAuth();
        window.location.href = '/auth/login';
        return Promise.reject(error);
      }
      if (isRefreshing) {
        return new Promise((resolve) => {
          refreshQueue.push((token: string) => {
            original.headers!.Authorization = `Bearer ${token}`;
            resolve(api(original));
          });
        });
      }
      isRefreshing = true;
      try {
        const { data } = await axios.post(`${API_BASE}/api/v1/auth/refresh`, {
          refresh_token: refreshToken,
        });
        setAuth(data.access_token, data.refresh_token);
        refreshQueue.forEach((cb) => cb(data.access_token));
        refreshQueue = [];
        original.headers!.Authorization = `Bearer ${data.access_token}`;
        return api(original);
      } catch {
        clearAuth();
        window.location.href = '/auth/login';
        return Promise.reject(error);
      } finally {
        isRefreshing = false;
      }
    }
    return Promise.reject(error);
  }
);

export function setAuth(accessToken: string, refreshToken: string) {
  const isSecure = typeof window !== 'undefined' && window.location.protocol === 'https:';
  // Use secure cookies only when served over HTTPS (production). Use lax sameSite for cross-site navigations.
  Cookies.set('access_token', accessToken, { secure: isSecure, sameSite: 'lax', expires: 1 / 48 });
  Cookies.set('refresh_token', refreshToken, { secure: isSecure, sameSite: 'lax', expires: 7 });
}

export function clearAuth() {
  Cookies.remove('access_token');
  Cookies.remove('refresh_token');
  Cookies.remove('current_org');
}

export function isAuthenticated(): boolean {
  return !!Cookies.get('access_token') || !!Cookies.get('refresh_token');
}

// Auth endpoints
export const authApi = {
  login: (email: string, password: string) =>
    api.post('/auth/login', { email, password }),
  register: (email: string, password: string, full_name: string) =>
    api.post('/auth/register', { email, password, full_name }),
  logout: () => api.post('/auth/logout'),
  me: () => api.get('/auth/me'),
};

// Org endpoints
export const orgApi = {
  list: () => api.get('/organizations/'),
  create: (data: { name: string; slug: string; description?: string }) =>
    api.post('/organizations/', data),
  get: (id: string) => api.get(`/organizations/${id}`),
  invite: (id: string, email: string, role: string) =>
    api.post(`/organizations/${id}/invite`, { email, role }),
};

// Scan endpoints
export const scanApi = {
  create: (data: object) => api.post('/scans/', data),
  list: (orgId: string, page = 1, status?: string) =>
    api.get('/scans/', { params: { organization_id: orgId, page, status } }),
  get: (id: string) => api.get(`/scans/${id}`),
  stop: (id: string) => api.post(`/scans/${id}/stop`),
  summary: (id: string) => api.get(`/scans/${id}/summary`),
};

// Findings endpoints
export const findingsApi = {
  list: (scanId: string, params?: object) =>
    api.get('/findings/', { params: { scan_id: scanId, ...params } }),
  get: (id: string) => api.get(`/findings/${id}`),
  update: (id: string, data: object) => api.patch(`/findings/${id}`, data),
};

// Report endpoints
export const reportApi = {
  pdf: (scanId: string) =>
    api.get(`/reports/${scanId}/pdf`, { responseType: 'blob' }),
  json: (scanId: string) =>
    api.get(`/reports/${scanId}/json`, { responseType: 'blob' }),
  csv: (scanId: string) =>
    api.get(`/reports/${scanId}/csv`, { responseType: 'blob' }),
};

export function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
