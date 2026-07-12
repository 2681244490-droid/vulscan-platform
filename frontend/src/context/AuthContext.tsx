import { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { User, LoginRequest, RegisterRequest } from '@/types';
import { authAPI } from '@/api';

interface AuthContextType {
  user: User | null;
  accessToken: string | null;
  isAuthenticated: boolean | undefined;
  loading: boolean;
  login: (request: LoginRequest) => Promise<void>;
  register: (request: RegisterRequest) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider = ({ children }: AuthProviderProps) => {
  const [user, setUser] = useState<User | null>(null);
  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    const initAuth = async () => {
      const token = localStorage.getItem('access_token');
      const refreshToken = localStorage.getItem('refresh_token');
      const savedUser = localStorage.getItem('user');

      if (token && savedUser) {
        try {
          // 静默验证 token 有效性
          const response = await fetch('/api/auth/me', {
            headers: { 'Authorization': `Bearer ${token}` },
          });

          if (response.ok) {
            // token 有效，恢复登录状态
            setAccessToken(token);
            try {
              setUser(JSON.parse(savedUser));
            } catch {
              localStorage.removeItem('user');
            }
          } else if (response.status === 401 && refreshToken) {
            // token 过期，尝试用 refresh_token 刷新
            try {
              const refreshResp = await fetch('/api/auth/refresh', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ refresh_token: refreshToken }),
              });

              if (refreshResp.ok) {
                const data = await refreshResp.json();
                localStorage.setItem('access_token', data.access_token);
                if (data.refresh_token) {
                  localStorage.setItem('refresh_token', data.refresh_token);
                }
                setAccessToken(data.access_token);
                try {
                  setUser(JSON.parse(savedUser));
                } catch {
                  localStorage.removeItem('user');
                }
              } else {
                // refresh 失败，清除登录状态
                localStorage.removeItem('access_token');
                localStorage.removeItem('refresh_token');
                localStorage.removeItem('user');
                setAccessToken(null);
                setUser(null);
              }
            } catch {
              // 网络错误，清除登录状态
              localStorage.removeItem('access_token');
              localStorage.removeItem('refresh_token');
              localStorage.removeItem('user');
              setAccessToken(null);
              setUser(null);
            }
          } else {
            // 无 refresh_token 或其他错误，清除登录状态
            localStorage.removeItem('access_token');
            localStorage.removeItem('refresh_token');
            localStorage.removeItem('user');
            setAccessToken(null);
            setUser(null);
          }
        } catch {
          // 网络错误，保持当前状态（假定为有效，等 API 调用再判断）
          setAccessToken(token);
          try {
            setUser(JSON.parse(savedUser));
          } catch {
            localStorage.removeItem('user');
          }
        }
      }

      setLoading(false);
    };

    initAuth();
  }, []);

  const login = async (request: LoginRequest): Promise<void> => {
    const response = await authAPI.login(request);
    const { access_token, refresh_token, user: userData } = response.data;

    localStorage.setItem('access_token', access_token);
    localStorage.setItem('refresh_token', refresh_token);
    localStorage.setItem('user', JSON.stringify(userData));

    setAccessToken(access_token);
    setUser(userData);
  };

  const register = async (request: RegisterRequest): Promise<void> => {
    await authAPI.register(request);
  };

  const logout = async (): Promise<void> => {
    const refreshToken = localStorage.getItem('refresh_token');
    if (refreshToken) {
      try {
        await authAPI.logout(refreshToken);
      } catch {
      }
    }

    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    localStorage.removeItem('user');

    setAccessToken(null);
    setUser(null);
  };

  const value: AuthContextType = {
    user,
    accessToken,
    isAuthenticated: loading ? undefined : !!accessToken && !!user,
    loading,
    login,
    register,
    logout,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};
