import { useState, useEffect } from 'react';
import { Layout, Menu, Button, Drawer } from 'antd';
import {
  ScanOutlined,
  AimOutlined,
  WarningOutlined,
  FileTextOutlined,
  BarChartOutlined,
  MenuOutlined,
  LogoutOutlined,
  SettingOutlined,
} from '@ant-design/icons';
import { useAuth } from '@/context/AuthContext';
import { useNavigate } from 'react-router-dom';

const { Sider } = Layout;

interface SidebarProps {
  currentPage: string;
  onPageChange: (page: string) => void;
}

export const Sidebar = ({ currentPage, onPageChange }: SidebarProps) => {
  const { logout } = useAuth();
  const navigate = useNavigate();
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [collapsed, setCollapsed] = useState(false);
  const [isMobile, setIsMobile] = useState(false);

  useEffect(() => {
    const checkMobile = () => {
      setIsMobile(window.innerWidth < 768);
      if (window.innerWidth < 768) {
        setCollapsed(true);
      }
    };
    checkMobile();
    window.addEventListener('resize', checkMobile);
    return () => window.removeEventListener('resize', checkMobile);
  }, []);

  const handleLogout = async () => {
    await logout();
    window.location.href = '/login';
  };

  const menuItems = [
    { key: 'dashboard', label: '仪表盘', icon: <BarChartOutlined /> },
    { key: 'targets', label: '目标管理', icon: <AimOutlined /> },
    { key: 'scan-tasks', label: '扫描任务', icon: <ScanOutlined /> },
    { key: 'vulnerabilities', label: '漏洞库', icon: <WarningOutlined /> },
    { key: 'reports', label: '扫描报告', icon: <FileTextOutlined /> },
    { type: 'divider' as const },
    { key: 'settings', label: '系统设置', icon: <SettingOutlined /> },
  ];

  const handleMenuClick = (key: string) => {
    onPageChange(key);
    navigate(`/${key}`);
    if (isMobile) {
      setDrawerOpen(false);
    }
  };

  return (
    <>
      <Sider
        breakpoint="lg"
        collapsedWidth={isMobile ? 0 : 80}
        collapsible
        collapsed={collapsed}
        onCollapse={setCollapsed}
        trigger={null}
        style={{
          background: '#001529',
          position: isMobile ? 'fixed' : 'relative',
          zIndex: isMobile ? 1000 : 10,
          height: '100vh',
          left: 0,
          top: 0,
          display: isMobile ? 'none' : 'block',
        }}
      >
        <div className="flex items-center justify-center h-16 bg-[#002140]">
          {collapsed ? (
            <span className="text-white text-xl font-bold">VS</span>
          ) : (
            <h1 className="text-white text-lg font-bold">VulScan Pro</h1>
          )}
        </div>
        <Menu
          theme="dark"
          mode="inline"
          selectedKeys={[currentPage]}
          items={menuItems}
          onClick={({ key }) => handleMenuClick(key)}
          className="mt-4"
        />
        <div className="absolute bottom-4 left-0 right-0 px-4">
          <Button
            type="text"
            danger
            icon={<LogoutOutlined />}
            onClick={handleLogout}
            className="w-full text-white/70 hover:text-white"
          >
            {!collapsed && '退出登录'}
          </Button>
        </div>
      </Sider>

      {/* Mobile Menu Button */}
      <Button
        type="text"
        icon={<MenuOutlined />}
        onClick={() => setDrawerOpen(true)}
        className="fixed top-4 left-4 z-50 md:hidden"
        style={{ background: '#001529', color: '#fff', borderRadius: 4 }}
      />

      {/* Mobile Drawer */}
      <Drawer
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        placement="left"
        className="md:hidden"
        width={200}
        styles={{ body: { padding: 0, background: '#001529' }, header: { display: 'none' } }}
      >
        <div className="flex items-center justify-center h-16 bg-[#002140]">
          <h1 className="text-white text-lg font-bold">VulScan Pro</h1>
        </div>
        <Menu
          theme="dark"
          mode="inline"
          selectedKeys={[currentPage]}
          items={menuItems}
          onClick={({ key }) => handleMenuClick(key)}
          className="mt-4"
        />
        <div className="absolute bottom-4 left-0 right-0 px-4">
          <Button
            type="text"
            danger
            icon={<LogoutOutlined />}
            onClick={handleLogout}
            className="w-full text-white/70 hover:text-white"
          >
            退出登录
          </Button>
        </div>
      </Drawer>
    </>
  );
};
