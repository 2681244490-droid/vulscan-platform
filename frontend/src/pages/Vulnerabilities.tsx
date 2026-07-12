import { useState, useEffect, useCallback } from 'react';
import {
  Table,
  Button,
  Drawer,
  App,
  Tag,
  Space,
  Tooltip,
  Select,
  Popconfirm,
  Badge,
  Card,
  Divider,
  Descriptions,
  Progress,
  Dropdown,
  Empty,
} from 'antd';
import {
  EyeOutlined,
  DeleteOutlined,
  ExportOutlined,
  CheckCircleOutlined,
  StopOutlined,
  VerifiedOutlined,
  FilterOutlined,
  DownloadOutlined,
  FileTextOutlined,
  BugOutlined,
  SafetyCertificateOutlined,
} from '@ant-design/icons';
import { vulnerabilityAPI } from '@/api';
import { Vulnerability, VulnerabilitySeverity } from '@/types';
import dayjs from 'dayjs';

const { Option } = Select;

const SEVERITY_CONFIG: Record<VulnerabilitySeverity, { color: string; label: string; score: [number, number] }> = {
  critical: { color: '#ff4d4f', label: '严重', score: [9.0, 10.0] },
  high: { color: '#fa8c16', label: '高危', score: [7.0, 8.9] },
  medium: { color: '#faad14', label: '中危', score: [4.0, 6.9] },
  low: { color: '#1890ff', label: '低危', score: [0.1, 3.9] },
  info: { color: '#8c8c8c', label: '信息', score: [0, 0] },
};

const STATUS_OPTIONS = [
  { value: 'open', label: '未处理', color: 'red' },
  { value: 'fixed', label: '已修复', color: 'green' },
  { value: 'ignored', label: '已忽略', color: 'gray' },
  { value: 'verified', label: '已验证', color: 'blue' },
];

export const Vulnerabilities = () => {
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(false);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [total, setTotal] = useState(0);
  const [severityFilter, setSeverityFilter] = useState<string | undefined>();
  const [statusFilter, setStatusFilter] = useState<string | undefined>();
  const [selectedRowKeys, setSelectedRowKeys] = useState<React.Key[]>([]);

  const [drawerVisible, setDrawerVisible] = useState(false);
  const [currentVulnerability, setCurrentVulnerability] = useState<Vulnerability | null>(null);
  const { message } = App.useApp();

  const fetchVulnerabilities = useCallback(async () => {
    setLoading(true);
    try {
      const res = await vulnerabilityAPI.list(page, pageSize, severityFilter, statusFilter);
      setVulnerabilities(res.data.data);
      setTotal(res.data.total);
    } catch {
      message.error('获取漏洞列表失败');
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, severityFilter, statusFilter]);

  useEffect(() => {
    fetchVulnerabilities();
  }, [fetchVulnerabilities]);

  const handleView = (vulnerability: Vulnerability) => {
    setCurrentVulnerability(vulnerability);
    setDrawerVisible(true);
  };

  const handleStatusChange = async (id: string, status: string) => {
    try {
      await vulnerabilityAPI.updateStatus(id, status);
      message.success('状态更新成功');
      fetchVulnerabilities();
      if (currentVulnerability?.id === id) {
        setCurrentVulnerability({ ...currentVulnerability, status: status as Vulnerability['status'] });
      }
    } catch {
      message.error('状态更新失败');
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await vulnerabilityAPI.delete(id);
      message.success('删除成功');
      fetchVulnerabilities();
    } catch {
      message.error('删除失败');
    }
  };

  const handleExport = async (format: 'json' | 'csv') => {
    try {
      const ids = selectedRowKeys.length > 0 ? selectedRowKeys as string[] : undefined;
      const res = await vulnerabilityAPI.export(format, ids);
      const blob = new Blob([res.data], {
        type: format === 'json' ? 'application/json' : 'text/csv',
      });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `vulnerabilities_${dayjs().format('YYYY-MM-DD_HH-mm-ss')}.${format}`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
      message.success(`导出 ${format.toUpperCase()} 成功`);
    } catch {
      message.error('导出失败');
    }
  };

  const getSeverityTag = (severity: string) => {
    const config = SEVERITY_CONFIG[severity as VulnerabilitySeverity];
    if (!config) return <Tag>{severity}</Tag>;
    return (
      <Tag color={config.color} className="font-medium">
        {config.label}
      </Tag>
    );
  };

  const getStatusTag = (status: string) => {
    const option = STATUS_OPTIONS.find((o) => o.value === status);
    if (!option) return <Tag>{status}</Tag>;
    return <Tag color={option.color}>{option.label}</Tag>;
  };

  const getCVSSColor = (score: number | null) => {
    if (score === null) return '#8c8c8c';
    if (score >= 9) return '#ff4d4f';
    if (score >= 7) return '#fa8c16';
    if (score >= 4) return '#faad14';
    return '#1890ff';
  };

  const columns = [
    {
      title: '漏洞标题',
      dataIndex: 'title',
      key: 'title',
      render: (text: string, record: Vulnerability) => (
        <div>
          <div className="font-medium">{text}</div>
          <div className="text-xs text-gray-400">{record.plugin_name}</div>
        </div>
      ),
      ellipsis: true,
    },
    {
      title: '严重级别',
      dataIndex: 'severity',
      key: 'severity',
      render: (s: string) => getSeverityTag(s),
      width: 90,
      filters: [
        { text: '严重', value: 'critical' },
        { text: '高危', value: 'high' },
        { text: '中危', value: 'medium' },
        { text: '低危', value: 'low' },
        { text: '信息', value: 'info' },
      ],
      onFilter: (value: React.Key | boolean, record: Vulnerability) => record.severity === value,
    },
    {
      title: 'CVSS',
      dataIndex: 'cvss_score',
      key: 'cvss_score',
      render: (s: number | null) =>
        s !== null ? (
          <span className="font-medium" style={{ color: getCVSSColor(s) }}>
            {s.toFixed(1)}
          </span>
        ) : (
          <span className="text-gray-400">-</span>
        ),
      width: 70,
    },
    {
      title: 'CVE',
      dataIndex: 'cve',
      key: 'cve',
      render: (c: string | null) => c || '-',
      width: 140,
      ellipsis: true,
    },
    {
      title: '目标',
      dataIndex: 'target_url',
      key: 'target_url',
      render: (t: string | undefined) => t || '-',
      ellipsis: true,
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      render: (s: string) => getStatusTag(s),
      width: 90,
    },
    {
      title: '发现时间',
      dataIndex: 'created_at',
      key: 'created_at',
      render: (t: string) => dayjs(t).format('MM-DD HH:mm'),
      width: 130,
    },
    {
      title: '操作',
      key: 'action',
      width: 160,
      render: (_: unknown, record: Vulnerability) => (
        <Space size="small">
          <Tooltip title="查看详情">
            <Button type="text" size="small" icon={<EyeOutlined />} onClick={() => handleView(record)} />
          </Tooltip>
          <Dropdown
            menu={{
              items: STATUS_OPTIONS.map((opt) => ({
                key: opt.value,
                label: opt.label,
                onClick: () => handleStatusChange(record.id, opt.value),
              })),
            }}
          >
            <Button type="text" size="small" icon={<CheckCircleOutlined />} />
          </Dropdown>
          <Popconfirm
            title="确认删除"
            description="确定要删除此漏洞记录吗？"
            onConfirm={() => handleDelete(record.id)}
            okText="删除"
            cancelText="取消"
            okButtonProps={{ danger: true }}
          >
            <Tooltip title="删除">
              <Button type="text" danger size="small" icon={<DeleteOutlined />} />
            </Tooltip>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  const rowSelection = {
    selectedRowKeys,
    onChange: (keys: React.Key[]) => setSelectedRowKeys(keys),
  };

  return (
    <div className="p-4 md:p-6 animate-fade-in">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center mb-6 gap-4">
        <h2 className="text-xl font-semibold">漏洞库</h2>
        <Space wrap>
          <Select
            placeholder="严重级别筛选"
            allowClear
            style={{ width: 130 }}
            onChange={(value) => {
              setSeverityFilter(value);
              setPage(1);
            }}
            suffixIcon={<FilterOutlined />}
          >
            <Option value="critical">严重</Option>
            <Option value="high">高危</Option>
            <Option value="medium">中危</Option>
            <Option value="low">低危</Option>
            <Option value="info">信息</Option>
          </Select>
          <Select
            placeholder="状态筛选"
            allowClear
            style={{ width: 120 }}
            onChange={(value) => {
              setStatusFilter(value);
              setPage(1);
            }}
          >
            {STATUS_OPTIONS.map((opt) => (
              <Option key={opt.value} value={opt.value}>
                {opt.label}
              </Option>
            ))}
          </Select>
          <Dropdown
            menu={{
              items: [
                { key: 'json', label: '导出 JSON', icon: <FileTextOutlined />, onClick: () => handleExport('json') },
                { key: 'csv', label: '导出 CSV', icon: <DownloadOutlined />, onClick: () => handleExport('csv') },
              ],
            }}
          >
            <Button icon={<ExportOutlined />}>
              导出{selectedRowKeys.length > 0 ? ` (${selectedRowKeys.length})` : ''}
            </Button>
          </Dropdown>
        </Space>
      </div>

      <Table
        dataSource={vulnerabilities}
        columns={columns}
        rowKey="id"
        loading={loading}
        rowSelection={rowSelection}
        pagination={{
          current: page,
          pageSize,
          total,
          showSizeChanger: true,
          pageSizeOptions: [10, 20, 50],
          showTotal: (t) => `共 ${t} 条`,
          onChange: (p, s) => {
            setPage(p);
            if (s) setPageSize(s);
          },
        }}
        scroll={{ x: 'max-content' }}
      />

      {/* Detail Drawer */}
      <Drawer
        title="漏洞详情"
        width={640}
        open={drawerVisible}
        onClose={() => setDrawerVisible(false)}
      >
        {currentVulnerability ? (
          <div>
            {/* Header */}
            <div className="flex items-start justify-between mb-6">
              <div>
                <h3 className="text-lg font-semibold mb-2">{currentVulnerability.title}</h3>
                <Space>
                  {getSeverityTag(currentVulnerability.severity)}
                  {getStatusTag(currentVulnerability.status)}
                  {currentVulnerability.cve && <Tag color="purple">{currentVulnerability.cve}</Tag>}
                </Space>
              </div>
              {currentVulnerability.cvss_score !== null && (
                <div className="text-center">
                  <Progress
                    type="circle"
                    percent={currentVulnerability.cvss_score * 10}
                    width={80}
                    strokeColor={getCVSSColor(currentVulnerability.cvss_score)}
                    format={() => {
                      const score = currentVulnerability.cvss_score ?? 0;
                      return (
                        <span style={{ color: getCVSSColor(score), fontWeight: 'bold' }}>
                          {score.toFixed(1)}
                        </span>
                      );
                    }}
                  />
                  <div className="text-xs text-gray-400 mt-1">CVSS评分</div>
                </div>
              )}
            </div>

            <Divider />

            {/* Basic Info */}
            <Descriptions bordered column={1} size="small" className="mb-6">
              <Descriptions.Item label="插件">{currentVulnerability.plugin_name}</Descriptions.Item>
              <Descriptions.Item label="目标">{currentVulnerability.target_url || '-'}</Descriptions.Item>
              <Descriptions.Item label="发现时间">
                {dayjs(currentVulnerability.created_at).format('YYYY-MM-DD HH:mm:ss')}
              </Descriptions.Item>
              <Descriptions.Item label="更新时间">
                {dayjs(currentVulnerability.updated_at).format('YYYY-MM-DD HH:mm:ss')}
              </Descriptions.Item>
            </Descriptions>

            {/* Description */}
            <Card size="small" title={<><BugOutlined /> 漏洞描述</>} className="mb-4">
              <p className="text-sm whitespace-pre-wrap">{currentVulnerability.description}</p>
            </Card>

            {/* Payload */}
            {currentVulnerability.payload && (
              <Card size="small" title={<><FileTextOutlined /> Payload</>} className="mb-4">
                <pre className="bg-gray-100 dark:bg-gray-800 p-3 rounded text-sm overflow-x-auto">
                  {currentVulnerability.payload}
                </pre>
              </Card>
            )}

            {/* Proof */}
            {currentVulnerability.proof && (
              <Card size="small" title={<><VerifiedOutlined /> 验证证据</>} className="mb-4">
                <pre className="bg-gray-100 dark:bg-gray-800 p-3 rounded text-sm overflow-x-auto">
                  {currentVulnerability.proof}
                </pre>
              </Card>
            )}

            {/* Remediation */}
            <Card size="small" title={<><SafetyCertificateOutlined /> 修复建议</>} className="mb-6">
              <p className="text-sm whitespace-pre-wrap">{currentVulnerability.remediation}</p>
            </Card>

            {/* Actions */}
            <div className="flex gap-3">
              <Button
                type="primary"
                icon={<CheckCircleOutlined />}
                onClick={() => handleStatusChange(currentVulnerability.id, 'fixed')}
                disabled={currentVulnerability.status === 'fixed'}
              >
                标记已修复
              </Button>
              <Button
                icon={<VerifiedOutlined />}
                onClick={() => handleStatusChange(currentVulnerability.id, 'verified')}
                disabled={currentVulnerability.status === 'verified'}
              >
                标记已验证
              </Button>
              <Button
                icon={<StopOutlined />}
                onClick={() => handleStatusChange(currentVulnerability.id, 'ignored')}
                disabled={currentVulnerability.status === 'ignored'}
              >
                忽略
              </Button>
            </div>
          </div>
        ) : (
          <Empty description="无数据" />
        )}
      </Drawer>
    </div>
  );
};
