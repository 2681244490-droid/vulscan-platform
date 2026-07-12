import { useState, useEffect } from 'react';
import { Layout, Button, Badge, Dropdown, Space, List, Typography } from 'antd';
import {
  BellOutlined,
  MoonOutlined,
  SunOutlined,
  UserOutlined,
  SettingOutlined,
  LogoutOutlined,
} from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '@/context/AuthContext';
import { useTheme } from '@/context/ThemeContext';

const { Header: AntHeader } = Layout;

interface Notification {
  id: string;
  title: string;
  description: string;
  time: string;
  read: boolean;
  link?: string;
}

export const Header = () => {
  const { user, logout } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const navigate = useNavigate();

  const defaultNotifications: Notification[] = [
    { id: '1', title: '扫描任务完成', description: 'ljbljb.com 扫描完成，发现 60 个漏洞', time: '5分钟前', read: false, link: '/scan-tasks' },
    { id: '2', title: '新漏洞发现', description: 'ljblib.xyz 发现高危漏洞', time: '10分钟前', read: false, link: '/vulnerabilities' },
    { id: '3', title: '系统通知', description: '系统已成功启动所有服务', time: '30分钟前', read: true },
  ];

  const loadNotifications = (): Notification[] => {
    try {
      const saved = localStorage.getItem('notifications');
      if (saved) return JSON.parse(saved);
    } catch {}
    return defaultNotifications;
  };

  const [notifications, setNotifications] = useState<Notification[]>(loadNotifications);

  useEffect(() => {
    localStorage.setItem('notifications', JSON.stringify(notifications));
  }, [notifications]);

  const unreadCount = notifications.filter(n => !n.read).length;

  const markAllRead = () => {
    setNotifications(ns => ns.map(n => ({ ...n, read: true })));
  };

  const markAsRead = (id: string) => {
    setNotifications(ns => ns.map(n => n.id === id ? { ...n, read: true } : n));
  };

  const handleNotificationClick = (item: Notification) => {
    markAsRead(item.id);
    if (item.link) {
      navigate(item.link);
    }
  };

  const notificationItems = {
    items: [
      {
        key: 'header',
        label: (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 16px', borderBottom: '1px solid rgba(0,0,0,0.06)' }}>
            <span style={{ fontWeight: 500 }}>通知中心</span>
            <Button type="link" size="small" onClick={(e) => { e.stopPropagation(); markAllRead(); }}>全部已读</Button>
          </div>
        ),
      },
      {
        key: 'list',
        label: (
          <List
            dataSource={notifications.slice(0, 5)}
            style={{ maxHeight: 320, overflowY: 'auto', width: 360 }}
            renderItem={(item) => (
              <List.Item
                style={{ padding: '8px 16px', cursor: 'pointer', opacity: item.read ? 0.6 : 1 }}
                onClick={() => handleNotificationClick(item)}
              >
                <List.Item.Meta
                  avatar={<Badge dot={!item.read} />}
                  title={item.title}
                  description={<Typography.Text ellipsis style={{ maxWidth: 200 }}>{item.description}</Typography.Text>}
                />
                <span style={{ fontSize: 12, color: '#999' }}>{item.time}</span>
              </List.Item>
            )}
          />
        ),
      },
      {
        key: 'footer',
        label: (
          <div style={{ textAlign: 'center', padding: '8px 0', borderTop: '1px solid rgba(0,0,0,0.06)' }}>
            <Button type="link" size="small">查看全部通知</Button>
          </div>
        ),
      },
    ],
  };

  const handleLogout = async () => {
    await logout();
    window.location.href = '/login';
  };

  const userMenuItems = [
    {
      key: 'profile',
      icon: <UserOutlined />,
      label: '个人中心',
      onClick: () => navigate('/settings'),
    },
    {
      key: 'settings',
      icon: <SettingOutlined />,
      label: '系统设置',
      onClick: () => navigate('/settings'),
    },
    {
      type: 'divider' as const,
    },
    {
      key: 'logout',
      icon: <LogoutOutlined />,
      label: '退出登录',
      danger: true,
      onClick: handleLogout,
    },
  ];

  return (
    <AntHeader
      style={{
        padding: '0 24px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        position: 'sticky',
        top: 0,
        zIndex: 100,
        transition: 'background 0.3s ease',
      }}
    >
      <h2
        className="text-lg md:text-xl font-semibold truncate"
        style={{ color: theme === 'dark' ? '#e0e0e0' : '#1f2937' }}
      >
        {user?.username} 的安全扫描平台
      </h2>

      <Space size="middle" className="flex items-center">
        <Button
          type="text"
          icon={
            theme === 'dark' ? (
              <SunOutlined style={{ color: '#faad14' }} />
            ) : (
              <MoonOutlined style={{ color: '#595959' }} />
            )
          }
          onClick={toggleTheme}
          aria-label="切换主题"
        />

        <Dropdown menu={notificationItems} trigger={['click']} placement="bottomRight">
          <Badge count={unreadCount} size="small">
            <Button type="text" icon={<BellOutlined />} aria-label="通知" />
          </Badge>
        </Dropdown>

        <Dropdown
          menu={{ items: userMenuItems }}
          placement="bottomRight"
          arrow
        >
          <div className="flex items-center gap-2 cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-800 px-3 py-1 rounded-lg transition-colors">
            <div
              className="w-8 h-8 rounded-full flex items-center justify-center text-white text-sm font-medium"
              style={{ background: '#1890ff' }}
            >
              {user?.username?.charAt(0).toUpperCase() || 'U'}
            </div>
            <div className="hidden md:block">
              <div
                className="text-sm font-medium"
                style={{ color: theme === 'dark' ? '#e0e0e0' : '#1f2937' }}
              >
                {user?.username}
              </div>
              <div className="text-xs text-gray-400">{user?.email}</div>
            </div>
          </div>
        </Dropdown>
      </Space>
    </AntHeader>
  );
};
