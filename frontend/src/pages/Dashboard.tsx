import { useEffect, useState, useCallback } from 'react';
import { Card, Row, Col, Statistic, Table, Tag, Radio, Spin, App } from 'antd';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  LineChart,
  Line,
  PieChart,
  Pie,
  Cell,
} from 'recharts';
import {
  ScanOutlined,
  WarningOutlined,
  ToolOutlined,
  GlobalOutlined,
  ClockCircleOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
  LoadingOutlined,
} from '@ant-design/icons';
import { dashboardAPI, scanTaskAPI, vulnerabilityAPI } from '@/api';
import { ScanTask, Vulnerability, DashboardStats, TrendData } from '@/types';
import { useLanguage } from '@/context/LanguageContext';
import dayjs from 'dayjs';

const SEVERITY_COLORS = {
  critical: '#ff4d4f',
  high: '#fa8c16',
  medium: '#faad14',
  low: '#1890ff',
  info: '#8c8c8c',
};

const PIE_COLORS = ['#ff4d4f', '#fa8c16', '#faad14', '#1890ff', '#52c41a', '#8c8c8c'];

const TIME_RANGES = [
  { labelKey: 'byDay', value: 'day' },
  { labelKey: 'byWeek', value: 'week' },
  { labelKey: 'byMonth', value: 'month' },
];

export const Dashboard = () => {
  const { t } = useLanguage();
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [recentTasks, setRecentTasks] = useState<ScanTask[]>([]);
  const [recentVulnerabilities, setRecentVulnerabilities] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [timeRange, setTimeRange] = useState<'day' | 'week' | 'month'>('day');
  const [trendData, setTrendData] = useState<TrendData[]>([]);
  const { message } = App.useApp();

  const fetchStats = useCallback(async () => {
    try {
      const res = await dashboardAPI.getStats();
      setStats(res.data);
      setTrendData(res.data.scan_trend);
    } catch {
      message.error(t('fetchStatsFailed'));
    }
  }, [t]);

  const fetchRecentTasks = useCallback(async () => {
    try {
      const res = await scanTaskAPI.list(1, 5);
      setRecentTasks(res.data.data);
    } catch {
      message.error(t('fetchTasksFailed'));
    }
  }, [t]);

  const fetchRecentVulnerabilities = useCallback(async () => {
    try {
      const res = await vulnerabilityAPI.list(1, 5);
      setRecentVulnerabilities(res.data.data);
    } catch {
      message.error(t('fetchVulnerabilitiesFailed'));
    }
  }, [t]);

  useEffect(() => {
    const init = async () => {
      setLoading(true);
      await Promise.all([fetchStats(), fetchRecentTasks(), fetchRecentVulnerabilities()]);
      setLoading(false);
    };
    init();
  }, [fetchStats, fetchRecentTasks, fetchRecentVulnerabilities]);

  // Aggregate real trend data by time range
  useEffect(() => {
    if (!stats?.scan_trend || stats.scan_trend.length === 0) return;

    const raw = stats.scan_trend;
    if (timeRange === 'day') {
      // Show daily data, format date as MM-DD
      setTrendData(
        raw.map((d) => ({
          ...d,
          date: d.date.slice(5), // "2025-01-15" -> "01-15"
        }))
      );
    } else if (timeRange === 'week') {
      // Aggregate by week (ISO week number)
      const weekMap = new Map<string, { count: number; high_risk: number; medium_risk: number; low_risk: number }>();
      raw.forEach((d) => {
        const dt = dayjs(d.date);
        const weekLabel = `${dt.year()}-${String(Math.ceil(dt.date() / 7)).padStart(2, '0')}`;
        const entry = weekMap.get(weekLabel) || { count: 0, high_risk: 0, medium_risk: 0, low_risk: 0 };
        entry.count += d.count;
        entry.high_risk += d.high_risk;
        entry.medium_risk += d.medium_risk;
        entry.low_risk += d.low_risk;
        weekMap.set(weekLabel, entry);
      });
      setTrendData(
        Array.from(weekMap.entries()).map(([date, v]) => ({ date, ...v }))
      );
    } else {
      // Aggregate by month
      const monthMap = new Map<string, { count: number; high_risk: number; medium_risk: number; low_risk: number }>();
      raw.forEach((d) => {
        const monthLabel = d.date.slice(0, 7); // "2025-01"
        const entry = monthMap.get(monthLabel) || { count: 0, high_risk: 0, medium_risk: 0, low_risk: 0 };
        entry.count += d.count;
        entry.high_risk += d.high_risk;
        entry.medium_risk += d.medium_risk;
        entry.low_risk += d.low_risk;
        monthMap.set(monthLabel, entry);
      });
      setTrendData(
        Array.from(monthMap.entries()).map(([date, v]) => ({ date, ...v }))
      );
    }
  }, [timeRange, stats]);

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'running':
        return <LoadingOutlined className="text-blue-500" />;
      case 'completed':
        return <CheckCircleOutlined className="text-green-500" />;
      case 'failed':
        return <CloseCircleOutlined className="text-red-500" />;
      case 'pending':
        return <ClockCircleOutlined className="text-yellow-500" />;
      default:
        return <ClockCircleOutlined className="text-gray-500" />;
    }
  };

  const getStatusTag = (status: string) => {
    switch (status) {
      case 'running':
        return <Tag color="blue">{t('scanRunning')}</Tag>;
      case 'completed':
        return <Tag color="green">{t('scanCompleted')}</Tag>;
      case 'failed':
        return <Tag color="red">{t('scanFailed')}</Tag>;
      case 'pending':
        return <Tag color="yellow">{t('scanPending')}</Tag>;
      case 'paused':
        return <Tag color="orange">{t('scanPaused')}</Tag>;
      case 'cancelled':
        return <Tag>{t('scanCancelled')}</Tag>;
      default:
        return <Tag>{status}</Tag>;
    }
  };

  const getSeverityTag = (severity: string) => {
    switch (severity) {
      case 'critical':
        return <Tag color="red">{t('critical')}</Tag>;
      case 'high':
        return <Tag color="orange">{t('high')}</Tag>;
      case 'medium':
        return <Tag color="yellow">{t('medium')}</Tag>;
      case 'low':
        return <Tag color="blue">{t('low')}</Tag>;
      default:
        return <Tag color="gray">{t('info')}</Tag>;
    }
  };

  const taskColumns = [
    { title: t('taskName'), dataIndex: 'name', key: 'name', ellipsis: true },
    { title: t('status'), dataIndex: 'status', key: 'status', render: (status: string) => getStatusTag(status), width: 90 },
    { title: t('scanProgress'), dataIndex: 'progress', key: 'progress', render: (p: number) => <span className="text-sm">{p}%</span>, width: 60 },
    { title: t('created'), dataIndex: 'created_at', key: 'created_at', render: (t: string) => dayjs(t).format('MM-DD HH:mm'), width: 130 },
  ];

  const vulnColumns = [
    { title: t('title'), dataIndex: 'title', key: 'title', ellipsis: true },
    { title: t('severity'), dataIndex: 'severity', key: 'severity', render: (s: string) => getSeverityTag(s), width: 80 },
    { title: t('target'), dataIndex: 'target_url', key: 'target_url', render: (t: string | undefined) => t || '-', ellipsis: true },
    { title: t('created'), dataIndex: 'created_at', key: 'created_at', render: (t: string) => dayjs(t).format('MM-DD HH:mm'), width: 130 },
  ];

  if (loading) {
    return (
      <div className="min-h-[400px] flex items-center justify-center">
        <Spin size="large" spinning>{t('loading')}</Spin>
      </div>
    );
  }

  return (
    <div className="p-4 md:p-6 animate-fade-in">
      <h2 className="text-xl font-semibold mb-6">{t('dashboard')}</h2>

      {/* Stats Cards */}
      <Row gutter={[16, 16]} className="mb-6">
        <Col xs={12} sm={12} lg={6}>
          <Card hoverable className="dashboard-stat-card">
            <Statistic
              title={t('todayScans')}
              value={stats?.today_scans || 0}
              prefix={<ScanOutlined className="text-blue-500 mr-2" />}
              valueStyle={{ color: '#1890ff', fontSize: '28px' }}
            />
            <div className="text-xs text-gray-400 mt-2">{t('todayScansDesc')}</div>
          </Card>
        </Col>
        <Col xs={12} sm={12} lg={6}>
          <Card hoverable className="dashboard-stat-card">
            <Statistic
              title={t('highRiskVulnerabilities')}
              value={stats?.high_risk_count || 0}
              prefix={<WarningOutlined className="text-red-500 mr-2" />}
              valueStyle={{ color: '#ff4d4f', fontSize: '28px' }}
            />
            <div className="text-xs text-gray-400 mt-2">{t('highRiskVulnerabilitiesDesc')}</div>
          </Card>
        </Col>
        <Col xs={12} sm={12} lg={6}>
          <Card hoverable className="dashboard-stat-card">
            <Statistic
              title={t('pendingVulnerabilities')}
              value={stats?.pending_fix_count || 0}
              prefix={<ToolOutlined className="text-orange-500 mr-2" />}
              valueStyle={{ color: '#fa8c16', fontSize: '28px' }}
            />
            <div className="text-xs text-gray-400 mt-2">{t('pendingVulnerabilitiesDesc')}</div>
          </Card>
        </Col>
        <Col xs={12} sm={12} lg={6}>
          <Card hoverable className="dashboard-stat-card">
            <Statistic
              title={t('totalTargets')}
              value={stats?.total_targets || 0}
              prefix={<GlobalOutlined className="text-green-500 mr-2" />}
              valueStyle={{ color: '#52c41a', fontSize: '28px' }}
            />
            <div className="text-xs text-gray-400 mt-2">{t('totalTargetsDesc')}</div>
          </Card>
        </Col>
      </Row>

      {/* Charts Row 1: Trend */}
      <Row gutter={[16, 16]} className="mb-6">
        <Col xs={24} lg={16}>
          <Card
            title={t('scanTrend')}
            extra={
              <Radio.Group value={timeRange} onChange={(e) => setTimeRange(e.target.value)} size="small">
                {TIME_RANGES.map((r) => (
                  <Radio.Button key={r.value} value={r.value}>
                    {t(r.labelKey)}
                  </Radio.Button>
                ))}
              </Radio.Group>
            }
            variant="borderless"
          >
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={trendData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
                <XAxis dataKey="date" tick={{ fontSize: 12 }} />
                <YAxis tick={{ fontSize: 12 }} />
                <Tooltip
                  contentStyle={{
                    background: '#fff',
                    border: '1px solid #f0f0f0',
                    borderRadius: '8px',
                    boxShadow: '0 4px 12px rgba(0,0,0,0.1)',
                  }}
                />
                <Legend />
                <Line type="monotone" dataKey="count" name={t('totalScans')} stroke="#1890ff" strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="high_risk" name={t('high')} stroke="#ff4d4f" strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="medium_risk" name={t('medium')} stroke="#faad14" strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="low_risk" name={t('low')} stroke="#52c41a" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </Card>
        </Col>
        <Col xs={24} lg={8}>
          <Card title={t('vulnerabilityTypeDistribution')} variant="borderless">
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={stats?.vulnerability_distribution || []}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={100}
                  paddingAngle={2}
                  dataKey="value"
                  nameKey="name"
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                  labelLine={false}
                >
                  {(stats?.vulnerability_distribution || []).map((_, index) => (
                    <Cell key={`cell-${index}`} fill={PIE_COLORS[index % PIE_COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </Card>
        </Col>
      </Row>

      {/* Charts Row 2: Severity Distribution */}
      <Row gutter={[16, 16]} className="mb-6">
        <Col xs={24} lg={12}>
          <Card title={t('severityDistribution')} variant="borderless">
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={stats?.severity_distribution || []}>
                <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
                <XAxis dataKey="name" tick={{ fontSize: 12 }} />
                <YAxis tick={{ fontSize: 12 }} />
                <Tooltip
                  contentStyle={{
                    background: '#fff',
                    border: '1px solid #f0f0f0',
                    borderRadius: '8px',
                  }}
                />
                <Bar dataKey="value" name={t('vulnerabilityCount')} radius={[4, 4, 0, 0]}>
                  {(stats?.severity_distribution || []).map((entry, index) => {
                    const key = entry.name.toLowerCase() as keyof typeof SEVERITY_COLORS;
                    return <Cell key={`cell-${index}`} fill={SEVERITY_COLORS[key] || PIE_COLORS[index]} />;
                  })}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </Card>
        </Col>
        <Col xs={24} lg={12}>
          <Card title={t('recentScanTasks')} variant="borderless">
            <Table
              dataSource={recentTasks}
              columns={taskColumns}
              rowKey="id"
              pagination={false}
              size="small"
              scroll={{ x: 'max-content' }}
            />
          </Card>
        </Col>
      </Row>

      {/* Recent Vulnerabilities */}
      <Row gutter={[16, 16]}>
        <Col xs={24}>
          <Card title={t('recentVulnerabilities')} variant="borderless">
            <Table
              dataSource={recentVulnerabilities}
              columns={vulnColumns}
              rowKey="id"
              pagination={false}
              size="small"
              scroll={{ x: 'max-content' }}
            />
          </Card>
        </Col>
      </Row>
    </div>
  );
};
