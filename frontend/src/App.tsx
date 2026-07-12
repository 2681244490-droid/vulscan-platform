import { useState, useEffect, lazy, Suspense } from 'react';
import { Layout, Spin, ConfigProvider, theme as antTheme, App as AntdApp } from 'antd';
import { Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { AuthProvider, useAuth } from '@/context/AuthContext';
import { ThemeProvider, useTheme } from '@/context/ThemeContext';
import { LanguageProvider, useLanguage } from '@/context/LanguageContext';
import { Sidebar } from '@/components/Sidebar';
import { Header } from '@/components/Header';
import { ErrorBoundary } from '@/components/ErrorBoundary';

const Login = lazy(() => import('@/pages/Login').then(m => ({ default: m.Login })));
const Dashboard = lazy(() => import('@/pages/Dashboard').then(m => ({ default: m.Dashboard })));
const Targets = lazy(() => import('@/pages/Targets').then(m => ({ default: m.Targets })));
const ScanTasks = lazy(() => import('@/pages/ScanTasks').then(m => ({ default: m.ScanTasks })));
const Vulnerabilities = lazy(() => import('@/pages/Vulnerabilities').then(m => ({ default: m.Vulnerabilities })));
const Reports = lazy(() => import('@/pages/Reports').then(m => ({ default: m.Reports })));
const Settings = lazy(() => import('@/pages/Settings').then(m => ({ default: m.Settings })));

const { Content } = Layout;

interface ProtectedRouteProps {
  children: React.ReactNode;
}

const ProtectedRoute = ({ children }: ProtectedRouteProps) => {
  const { isAuthenticated } = useAuth();

  if (isAuthenticated === undefined) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <Spin size="large" spinning>加载中...</Spin>
      </div>
    );
  }

  return isAuthenticated ? <>{children}</> : <Navigate to="/login" />;
};

const AppContent = () => {
  const location = useLocation();
  const [currentPage, setCurrentPage] = useState('dashboard');
  const { theme } = useTheme();

  useEffect(() => {
    const path = location.pathname.replace('/', '');
    if (path) {
      setCurrentPage(path);
    } else {
      setCurrentPage('dashboard');
    }
  }, [location]);

  const handlePageChange = (page: string) => {
    setCurrentPage(page);
  };

  const isDark = theme === 'dark';

  return (
    <ConfigProvider
      theme={{
        algorithm: isDark ? antTheme.darkAlgorithm : antTheme.defaultAlgorithm,
        token: {
          colorPrimary: isDark ? '#0A84FF' : '#007AFF',
          borderRadius: 12,
          fontFamily: "'HarmonyOS Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif",
          colorBgContainer: isDark ? '#1c1c1e' : '#ffffff',
          colorBgLayout: isDark ? '#000000' : '#f2f2f7',
          colorBorder: isDark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.04)',
          colorBorderSecondary: isDark ? 'rgba(255,255,255,0.04)' : 'rgba(0,0,0,0.02)',
          boxShadow: isDark
            ? '0 2px 12px rgba(0,0,0,0.3)'
            : '0 2px 12px rgba(0,0,0,0.06)',
        },
      }}
    >
      <AntdApp>
        <Suspense fallback={<div className="min-h-screen flex items-center justify-center"><Spin size="large" spinning>加载中...</Spin></div>}>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route
              path="/*"
              element={
                <ProtectedRoute>
                  <Layout className="min-h-screen" hasSider>
                    <Sidebar currentPage={currentPage} onPageChange={handlePageChange} />
                    <Layout style={{ marginLeft: 0 }}>
                      <Header />
                      <Content
                        style={{
                          background: isDark ? '#000000' : '#f2f2f7',
                          minHeight: 'calc(100vh - 64px)',
                        }}
                      >
                        <Routes>
                          <Route path="/dashboard" element={<Dashboard />} />
                          <Route path="/targets" element={<Targets />} />
                          <Route path="/scan-tasks" element={<ScanTasks />} />
                          <Route path="/vulnerabilities" element={<Vulnerabilities />} />
                          <Route path="/reports" element={<Reports />} />
                          <Route path="/settings" element={<Settings />} />
                          <Route path="/" element={<Navigate to="/dashboard" />} />
                        </Routes>
                      </Content>
                    </Layout>
                  </Layout>
                </ProtectedRoute>
              }
            />
          </Routes>
        </Suspense>
      </AntdApp>
    </ConfigProvider>
  );
};

function App() {
  return (
    <ErrorBoundary>
      <LanguageProvider>
        <ThemeProvider>
          <AuthProvider>
            <AppContent />
          </AuthProvider>
        </ThemeProvider>
      </LanguageProvider>
    </ErrorBoundary>
  );
}

export default App;
