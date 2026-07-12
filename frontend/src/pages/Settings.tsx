import { useState } from 'react';
import { Card, Form, Input, Switch, Divider, Descriptions, Select, Button, message, Avatar, Layout, Menu, Typography, Space } from 'antd';
import {
  UserOutlined,
  LockOutlined,
  BellOutlined,
  SettingOutlined,
  InfoCircleOutlined,
  GlobalOutlined,
  BgColorsOutlined,
} from '@ant-design/icons';
import { useAuth } from '@/context/AuthContext';
import { useTheme } from '@/context/ThemeContext';
import { useLanguage } from '@/context/LanguageContext';

const { Text } = Typography;

type SettingsTab = 'profile' | 'security' | 'preferences' | 'notifications' | 'about';

export const Settings = () => {
  const { user } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const { language, setLanguage, t } = useLanguage();
  const [activeTab, setActiveTab] = useState<SettingsTab>('profile');

  const [passwordForm] = Form.useForm();
  const [notificationSettings, setNotificationSettings] = useState({
    email: true,
    scanComplete: true,
    vulnerability: true,
  });

  const handleChangePassword = (values: { oldPassword: string; newPassword: string }) => {
    message.success(t('passwordChanged'));
    passwordForm.resetFields();
  };

  const menuItems = [
    { key: 'profile' as SettingsTab, icon: <UserOutlined />, label: t('personalProfile') },
    { key: 'security' as SettingsTab, icon: <LockOutlined />, label: t('securitySettings') },
    { key: 'preferences' as SettingsTab, icon: <SettingOutlined />, label: t('systemPreferences') },
    { key: 'notifications' as SettingsTab, icon: <BellOutlined />, label: t('notificationSettings') },
    { key: 'about' as SettingsTab, icon: <InfoCircleOutlined />, label: t('about') },
  ];

  const renderContent = () => {
    switch (activeTab) {
      case 'profile':
        return (
          <Card title={t('personalProfile')} bordered={false}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 24, marginBottom: 24 }}>
              <Avatar size={80} style={{ backgroundColor: '#1890ff', fontSize: 32 }}>
                {user?.username?.charAt(0).toUpperCase() || 'U'}
              </Avatar>
              <div>
                <Typography.Title level={4} style={{ margin: 0 }}>{user?.username}</Typography.Title>
                <Text type="secondary">{user?.role === 'admin' ? t('admin') : t('normalUser')}</Text>
              </div>
            </div>
            <Descriptions bordered column={1}>
              <Descriptions.Item label={t('username')}>{user?.username}</Descriptions.Item>
              <Descriptions.Item label={t('email')}>{user?.email}</Descriptions.Item>
              <Descriptions.Item label={t('role')}>{user?.role === 'admin' ? t('admin') : t('normalUser')}</Descriptions.Item>
              <Descriptions.Item label={t('status')}>
                <span style={{ color: user?.is_active ? '#52c41a' : '#ff4d4f' }}>
                  {user?.is_active ? t('active') : t('disabled')}
                </span>
              </Descriptions.Item>
              <Descriptions.Item label={t('registrationTime')}>{user?.created_at ? new Date(user.created_at).toLocaleString(language) : '-'}</Descriptions.Item>
            </Descriptions>
          </Card>
        );

      case 'security':
        return (
          <Card title={t('changePassword')} bordered={false}>
            <Form
              form={passwordForm}
              onFinish={handleChangePassword}
              style={{ maxWidth: 480 }}
              layout="vertical"
            >
              <Form.Item
                name="oldPassword"
                label={t('oldPassword')}
                rules={[{ required: true, message: t('enterOldPassword') }]}
              >
                <Input.Password prefix={<LockOutlined />} placeholder={t('enterOldPassword')} />
              </Form.Item>
              <Form.Item
                name="newPassword"
                label={t('newPassword')}
                rules={[
                  { required: true, message: t('enterNewPassword') },
                  { min: 8, message: t('passwordMinLength') },
                ]}
              >
                <Input.Password prefix={<LockOutlined />} placeholder={t('enterNewPassword')} />
              </Form.Item>
              <Form.Item
                name="confirmPassword"
                label={t('confirmPassword')}
                dependencies={['newPassword']}
                rules={[
                  { required: true, message: t('enterNewPassword') },
                  ({ getFieldValue }) => ({
                    validator(_, value) {
                      if (!value || getFieldValue('newPassword') === value) {
                        return Promise.resolve();
                      }
                      return Promise.reject(new Error(t('passwordsNotMatch')));
                    },
                  }),
                ]}
              >
                <Input.Password prefix={<LockOutlined />} placeholder={t('enterNewPassword')} />
              </Form.Item>
              <Form.Item>
                <Button type="primary" htmlType="submit">
                  {t('changePassword')}
                </Button>
              </Form.Item>
            </Form>
          </Card>
        );

      case 'preferences':
        return (
          <Card title={t('systemPreferences')} bordered={false}>
            <div style={{ maxWidth: 480 }}>
              <div style={{ marginBottom: 24 }}>
                <div style={{ marginBottom: 8 }}>
                  <Space><GlobalOutlined /> {t('language')}</Space>
                </div>
                <Select
                  value={language}
                  onChange={(value) => setLanguage(value as 'zh-CN' | 'en-US')}
                  style={{ width: '100%' }}
                  options={[
                    { value: 'zh-CN', label: t('chinese') },
                    { value: 'en-US', label: t('english') },
                  ]}
                />
              </div>
              <Divider />
              <div>
                <div style={{ marginBottom: 8 }}>
                  <Space><BgColorsOutlined /> {t('theme')}</Space>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  <Switch
                    checked={theme === 'dark'}
                    onChange={toggleTheme}
                    checkedChildren={t('darkMode')}
                    unCheckedChildren={t('lightMode')}
                  />
                  <Text type="secondary">{t('current')}：{theme === 'dark' ? t('darkMode') : t('lightMode')}</Text>
                </div>
              </div>
            </div>
          </Card>
        );

      case 'notifications':
        return (
          <Card title={t('notificationSettings')} bordered={false}>
            <div style={{ maxWidth: 480 }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
                <div>
                  <div style={{ fontWeight: 500 }}>{t('emailNotifications')}</div>
                  <Text type="secondary" style={{ fontSize: 13 }}>{t('receiveEmailNotifications')}</Text>
                </div>
                <Switch
                  checked={notificationSettings.email}
                  onChange={(v) => setNotificationSettings(s => ({ ...s, email: v }))}
                />
              </div>
              <Divider style={{ margin: '16px 0' }} />
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
                <div>
                  <div style={{ fontWeight: 500 }}>{t('scanCompleteNotification')}</div>
                  <Text type="secondary" style={{ fontSize: 13 }}>{t('scanCompleteDesc')}</Text>
                </div>
                <Switch
                  checked={notificationSettings.scanComplete}
                  onChange={(v) => setNotificationSettings(s => ({ ...s, scanComplete: v }))}
                />
              </div>
              <Divider style={{ margin: '16px 0' }} />
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div>
                  <div style={{ fontWeight: 500 }}>{t('vulnerabilityNotification')}</div>
                  <Text type="secondary" style={{ fontSize: 13 }}>{t('vulnerabilityDesc')}</Text>
                </div>
                <Switch
                  checked={notificationSettings.vulnerability}
                  onChange={(v) => setNotificationSettings(s => ({ ...s, vulnerability: v }))}
                />
              </div>
            </div>
          </Card>
        );

      case 'about':
        return (
          <Card title={t('about')} bordered={false}>
            <Descriptions bordered column={1}>
              <Descriptions.Item label={t('systemName')}>VulScan Pro</Descriptions.Item>
              <Descriptions.Item label={t('version')}>v1.0.0</Descriptions.Item>
              <Descriptions.Item label={t('techStack')}>React + TypeScript + Ant Design + Rust (Backend)</Descriptions.Item>
              <Descriptions.Item label={t('description')}>{t('systemDescription')}</Descriptions.Item>
            </Descriptions>
          </Card>
        );

      default:
        return null;
    }
  };

  return (
    <div style={{ padding: '24px', maxWidth: 1200, margin: '0 auto' }}>
      <Typography.Title level={3} style={{ marginBottom: 24 }}>{t('settings')}</Typography.Title>
      <div style={{ display: 'flex', gap: 24 }}>
        <Card
          bordered={false}
          style={{ width: 220, flexShrink: 0, height: 'fit-content' }}
          bodyStyle={{ padding: '8px 0' }}
        >
          <Menu
            mode="inline"
            selectedKeys={[activeTab]}
            items={menuItems}
            onClick={({ key }) => setActiveTab(key as SettingsTab)}
            style={{ border: 'none' }}
          />
        </Card>
        <div style={{ flex: 1, minWidth: 0 }}>
          {renderContent()}
        </div>
      </div>
    </div>
  );
};
