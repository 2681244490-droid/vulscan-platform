import { useState, useEffect } from 'react';
import { Form, Input, Button, Tabs, App, Modal } from 'antd';
import { LockOutlined, UserOutlined, MailOutlined } from '@ant-design/icons';
import { useAuth } from '@/context/AuthContext';
import { useLanguage } from '@/context/LanguageContext';
import { useNavigate } from 'react-router-dom';

type Theme = 'dark' | 'light';

export const Login = () => {
  const { login, register } = useAuth();
  const { language, t } = useLanguage();
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('login');
  const [forgotPasswordVisible, setForgotPasswordVisible] = useState(false);
  const [theme, setTheme] = useState<Theme>(() => {
    const stored = localStorage.getItem('theme') as Theme;
    return stored || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  });
  const { message } = App.useApp();

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    document.documentElement.classList.toggle('dark', theme === 'dark');
  }, [theme]);

  const handleLogin = async (values: { email: string; password: string }) => {
    setLoading(true);
    try {
      await login(values);
      message.success(t('loginSuccess'));
      navigate('/dashboard');
    } catch (error) {
      message.error(t('loginFailed'));
    } finally {
      setLoading(false);
    }
  };

  const handleRegister = async (values: { username: string; email: string; password: string }) => {
    setLoading(true);
    try {
      await register(values);
      message.success(t('registerSuccess'));
      setActiveTab('login');
    } catch (error) {
      message.error(t('registerFailed'));
    } finally {
      setLoading(false);
    }
  };

  const isDark = theme === 'dark';

  return (
    <div className="min-h-screen flex items-center justify-center" style={{ background: isDark ? '#020617' : '#f2f2f7' }}>
      <div className="w-full max-w-[420px] px-6">
        <div className="text-center mb-10">
          <div className="inline-flex items-center justify-center w-20 h-20 rounded-[22px] mb-5 overflow-hidden" style={{ boxShadow: isDark ? '0 8px 24px rgba(34,197,94,0.2)' : '0 8px 24px rgba(0,122,255,0.2)' }}>
            <img src="/logo.jpg" alt="VulScan" className="w-full h-full object-cover" />
          </div>
          <h1 className="text-[28px] font-semibold tracking-tight" style={{ color: isDark ? '#f8fafc' : '#1f2937' }}>VulScan</h1>
          <p className="text-[15px] mt-2" style={{ color: isDark ? '#94a3b8' : '#6b7280' }}>{t('enterpriseWebVulnerabilityScanner')}</p>
        </div>

        <div className="rounded-3xl p-8" style={{ background: isDark ? '#0f172a' : '#ffffff', boxShadow: isDark ? '0 4px 24px rgba(0,0,0,0.4)' : '0 2px 20px rgba(0,0,0,0.04)', border: isDark ? '1px solid rgba(51,65,85,0.3)' : 'none' }}>
          <Tabs activeKey={activeTab} onChange={setActiveTab} centered items={[
            {
              key: 'login',
              label: <span className="text-[15px] font-medium" style={{ color: isDark ? '#f8fafc' : '#1f2937' }}>{t('login')}</span>,
              children: (
                <Form name="login" initialValues={{ email: '', password: '' }} onFinish={handleLogin} layout="vertical" requiredMark={false}>
                  <Form.Item name="email" label={<span className="text-[13px] font-medium" style={{ color: isDark ? '#94a3b8' : '#6b7280' }}>{t('email')}</span>} rules={[{ required: true, message: t('enterEmail') }, { type: 'email', message: t('validEmail') }]}>
                    <Input prefix={<MailOutlined style={{ color: isDark ? '#64748b' : '#8e8e93' }} />} placeholder={t('enterEmail')} className="h-12 rounded-xl" style={{ backgroundColor: isDark ? '#1e293b' : '#f5f5f7', border: 'none', color: isDark ? '#f8fafc' : '#1f2937' }} />
                  </Form.Item>
                  <Form.Item name="password" label={<span className="text-[13px] font-medium" style={{ color: isDark ? '#94a3b8' : '#6b7280' }}>{t('password')}</span>} rules={[{ required: true, message: t('enterPassword') }, { min: 8, message: t('passwordMinLength') }]}>
                    <Input.Password prefix={<LockOutlined style={{ color: isDark ? '#64748b' : '#8e8e93' }} />} placeholder={t('enterPassword')} className="h-12 rounded-xl" style={{ backgroundColor: isDark ? '#1e293b' : '#f5f5f7', border: 'none', color: isDark ? '#f8fafc' : '#1f2937' }} />
                  </Form.Item>
                  <Form.Item style={{ marginTop: 8 }}>
                    <Button type="primary" htmlType="submit" loading={loading} className="w-full h-12 rounded-xl text-[15px] font-semibold" style={{ background: isDark ? '#22c55e' : '#007AFF', border: 'none', boxShadow: isDark ? '0 4px 12px rgba(34,197,94,0.3)' : '0 4px 12px rgba(0,122,255,0.3)' }}>
                      {t('login')}
                    </Button>
                  </Form.Item>
                  <div className="text-right">
                    <a className="text-[13px] hover:text-blue-500" style={{ color: isDark ? '#64748b' : '#9ca3af' }} onClick={() => setForgotPasswordVisible(true)}>
                      {t('forgotPassword')}
                    </a>
                  </div>
                </Form>
              ),
            },
            {
              key: 'register',
              label: <span className="text-[15px] font-medium" style={{ color: isDark ? '#f8fafc' : '#1f2937' }}>{t('register')}</span>,
              children: (
                <Form name="register" initialValues={{ username: '', email: '', password: '' }} onFinish={handleRegister} layout="vertical" requiredMark={false}>
                  <Form.Item name="username" label={<span className="text-[13px] font-medium" style={{ color: isDark ? '#94a3b8' : '#6b7280' }}>{t('username')}</span>} rules={[{ required: true, message: t('enterUsername') }, { min: 3, message: t('enterUsername') }]}>
                    <Input prefix={<UserOutlined style={{ color: isDark ? '#64748b' : '#8e8e93' }} />} placeholder={t('enterUsername')} className="h-12 rounded-xl" style={{ backgroundColor: isDark ? '#1e293b' : '#f5f5f7', border: 'none', color: isDark ? '#f8fafc' : '#1f2937' }} />
                  </Form.Item>
                  <Form.Item name="email" label={<span className="text-[13px] font-medium" style={{ color: isDark ? '#94a3b8' : '#6b7280' }}>{t('email')}</span>} rules={[{ required: true, message: t('enterEmail') }, { type: 'email', message: t('validEmail') }]}>
                    <Input prefix={<MailOutlined style={{ color: isDark ? '#64748b' : '#8e8e93' }} />} placeholder={t('enterEmail')} className="h-12 rounded-xl" style={{ backgroundColor: isDark ? '#1e293b' : '#f5f5f7', border: 'none', color: isDark ? '#f8fafc' : '#1f2937' }} />
                  </Form.Item>
                  <Form.Item name="password" label={<span className="text-[13px] font-medium" style={{ color: isDark ? '#94a3b8' : '#6b7280' }}>{t('password')}</span>} rules={[{ required: true, message: t('enterPassword') }, { min: 8, message: t('passwordMinLength') }]}>
                    <Input.Password prefix={<LockOutlined style={{ color: isDark ? '#64748b' : '#8e8e93' }} />} placeholder={t('enterPassword')} className="h-12 rounded-xl" style={{ backgroundColor: isDark ? '#1e293b' : '#f5f5f7', border: 'none', color: isDark ? '#f8fafc' : '#1f2937' }} />
                  </Form.Item>
                  <Form.Item style={{ marginTop: 8 }}>
                    <Button type="primary" htmlType="submit" loading={loading} className="w-full h-12 rounded-xl text-[15px] font-semibold" style={{ background: isDark ? '#22c55e' : '#007AFF', border: 'none', boxShadow: isDark ? '0 4px 12px rgba(34,197,94,0.3)' : '0 4px 12px rgba(0,122,255,0.3)' }}>
                      {t('register')}
                    </Button>
                  </Form.Item>
                </Form>
              ),
            },
          ]} />
        </div>

        <p className="text-center text-[12px] mt-6" style={{ color: isDark ? '#64748b' : '#9ca3af' }}>
          {t('copyright')}
        </p>

        <Modal title={<span style={{ color: isDark ? '#f8fafc' : '#1f2937' }}>{t('resetPassword')}</span>} open={forgotPasswordVisible} onCancel={() => setForgotPasswordVisible(false)} footer={null}>
          <Form layout="vertical" style={{ marginTop: 16 }}>
            <Form.Item label={<span style={{ color: isDark ? '#94a3b8' : '#6b7280' }}>{t('email')}</span>}>
              <Input prefix={<MailOutlined style={{ color: isDark ? '#64748b' : '#8e8e93' }} />} placeholder={t('enterEmail')} style={{ backgroundColor: isDark ? '#1e293b' : '#ffffff', border: isDark ? '1px solid rgba(51,65,85,0.5)' : '1px solid rgba(0,0,0,0.1)', color: isDark ? '#f8fafc' : '#1f2937' }} />
            </Form.Item>
            <Button type="primary" block onClick={() => {
              message.success(t('sendResetLink'));
              setForgotPasswordVisible(false);
            }} style={{ background: isDark ? '#22c55e' : '#007AFF', border: 'none', height: 44, borderRadius: 12, boxShadow: isDark ? '0 4px 12px rgba(34,197,94,0.3)' : '0 4px 12px rgba(0,122,255,0.3)' }}>
              {t('sendResetLink')}
            </Button>
          </Form>
        </Modal>
      </div>
    </div>
  );
};
