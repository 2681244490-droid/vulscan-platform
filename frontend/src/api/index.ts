import axios, { AxiosError, AxiosInstance, AxiosResponse, CancelTokenSource } from 'axios';
import {
  LoginRequest,
  LoginResponse,
  RegisterRequest,
  User,
  RefreshTokenRequest,
  Target,
  CreateTargetRequest,
  ScanTask,
  CreateScanTaskRequest,
  Vulnerability,
  Report,
  PaginatedResponse,
  ErrorResponse,
  DashboardStats,
} from '@/types';

const API_BASE_URL = '/api';

const api: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request cancellation tokens storage
const pendingRequests = new Map<string, CancelTokenSource>();

const addPendingRequest = (key: string, source: CancelTokenSource) => {
  pendingRequests.set(key, source);
};

const removePendingRequest = (key: string) => {
  pendingRequests.delete(key);
};

export const cancelPendingRequests = (pattern?: string) => {
  pendingRequests.forEach((source, key) => {
    if (!pattern || key.includes(pattern)) {
      source.cancel('Request cancelled by user');
      removePendingRequest(key);
    }
  });
};

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }

  // Add cancel token
  const requestKey = `${config.method}_${config.url}_${JSON.stringify(config.params)}`;
  const source = axios.CancelToken.source();
  config.cancelToken = source.token;
  addPendingRequest(requestKey, source);

  return config;
});

api.interceptors.response.use(
  (response: AxiosResponse) => {
    const requestKey = `${response.config.method}_${response.config.url}_${JSON.stringify(response.config.params)}`;
    removePendingRequest(requestKey);
    return response;
  },
  async (error: AxiosError<ErrorResponse>) => {
    if (axios.isCancel(error)) {
      return Promise.reject(error);
    }

    const requestKey = `${error.config?.method}_${error.config?.url}_${JSON.stringify(error.config?.params)}`;
    removePendingRequest(requestKey);

    if (error.response?.status === 401) {
      const refreshToken = localStorage.getItem('refresh_token');
      if (refreshToken) {
        try {
          const response = await api.post<LoginResponse>('/auth/refresh', {
            refresh_token: refreshToken,
          });
          localStorage.setItem('access_token', response.data.access_token);
          localStorage.setItem('refresh_token', response.data.refresh_token);

          const originalRequest = error.config;
          if (originalRequest) {
            originalRequest.headers.Authorization = `Bearer ${response.data.access_token}`;
            return api(originalRequest);
          }
        } catch {
          localStorage.removeItem('access_token');
          localStorage.removeItem('refresh_token');
          localStorage.removeItem('user');
          window.location.href = '/login';
        }
      } else {
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        localStorage.removeItem('user');
        window.location.href = '/login';
      }
    }

    return Promise.reject(error);
  }
);

export const authAPI = {
  login: (request: LoginRequest): Promise<AxiosResponse<LoginResponse>> => {
    return api.post('/auth/login', request);
  },

  register: (request: RegisterRequest): Promise<AxiosResponse<User>> => {
    return api.post('/auth/register', request);
  },

  refreshToken: (request: RefreshTokenRequest): Promise<AxiosResponse<LoginResponse>> => {
    return api.post('/auth/refresh', request);
  },

  logout: (refreshToken: string): Promise<AxiosResponse<void>> => {
    return api.post('/auth/logout', { refresh_token: refreshToken });
  },
};

export const targetAPI = {
  list: (page: number, pageSize: number, search?: string): Promise<AxiosResponse<PaginatedResponse<Target>>> => {
    return api.get('/targets', { params: { page, page_size: pageSize, search } });
  },

  get: (id: string): Promise<AxiosResponse<Target>> => {
    return api.get(`/targets/${id}`);
  },

  create: (request: CreateTargetRequest): Promise<AxiosResponse<Target>> => {
    return api.post('/targets', request);
  },

  update: (id: string, request: CreateTargetRequest): Promise<AxiosResponse<Target>> => {
    return api.put(`/targets/${id}`, request);
  },

  delete: (id: string): Promise<AxiosResponse<void>> => {
    return api.delete(`/targets/${id}`);
  },

  batchCreate: (requests: CreateTargetRequest[]): Promise<AxiosResponse<{ created: number; failed: number }>> => {
    return api.post('/targets/batch', { targets: requests });
  },
};

export const scanTaskAPI = {
  list: (page: number, pageSize: number, status?: string): Promise<AxiosResponse<PaginatedResponse<ScanTask>>> => {
    return api.get('/scan-tasks', { params: { page, page_size: pageSize, status } });
  },

  get: (id: string): Promise<AxiosResponse<ScanTask>> => {
    return api.get(`/scan-tasks/${id}`);
  },

  create: (request: CreateScanTaskRequest): Promise<AxiosResponse<ScanTask>> => {
    return api.post('/scan-tasks', request);
  },

  pause: (id: string): Promise<AxiosResponse<ScanTask>> => {
    return api.put(`/scan-tasks/${id}/pause`);
  },

  resume: (id: string): Promise<AxiosResponse<ScanTask>> => {
    return api.put(`/scan-tasks/${id}/resume`);
  },

  cancel: (id: string): Promise<AxiosResponse<ScanTask>> => {
    return api.put(`/scan-tasks/${id}/cancel`);
  },

  delete: (id: string): Promise<AxiosResponse<void>> => {
    return api.delete(`/scan-tasks/${id}`);
  },
};

export const vulnerabilityAPI = {
  list: (
    page: number,
    pageSize: number,
    severity?: string,
    status?: string
  ): Promise<AxiosResponse<PaginatedResponse<Vulnerability>>> => {
    return api.get('/vulnerabilities', { params: { page, page_size: pageSize, severity, status } });
  },

  get: (id: string): Promise<AxiosResponse<Vulnerability>> => {
    return api.get(`/vulnerabilities/${id}`);
  },

  updateStatus: (id: string, status: string): Promise<AxiosResponse<Vulnerability>> => {
    return api.put(`/vulnerabilities/${id}/status`, { status });
  },

  delete: (id: string): Promise<AxiosResponse<void>> => {
    return api.delete(`/vulnerabilities/${id}`);
  },

  export: (format: 'json' | 'csv', ids?: string[]): Promise<AxiosResponse<Blob>> => {
    return api.post('/vulnerabilities/export', { format, ids }, { responseType: 'blob' });
  },
};

export const reportAPI = {
  list: (page: number, pageSize: number): Promise<AxiosResponse<PaginatedResponse<Report>>> => {
    return api.get('/reports', { params: { page, page_size: pageSize } });
  },

  get: (id: string): Promise<AxiosResponse<Report>> => {
    return api.get(`/reports/${id}`);
  },

  create: (taskId: string, template: string): Promise<AxiosResponse<Report>> => {
    return api.post('/reports', { task_id: taskId, template });
  },

  delete: (id: string): Promise<AxiosResponse<void>> => {
    return api.delete(`/reports/${id}`);
  },

  download: (id: string): Promise<AxiosResponse<Blob>> => {
    return api.get(`/reports/${id}/download`, { responseType: 'blob' });
  },
};

export const dashboardAPI = {
  getStats: (): Promise<AxiosResponse<DashboardStats>> => {
    return api.get('/dashboard/stats');
  },
};

export default api;
