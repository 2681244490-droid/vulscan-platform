import { useState, useEffect, useCallback } from 'react';
import {
  Table,
  Button,
  Modal,
  App,
  Tag,
  Space,
  Tooltip,
  Popconfirm,
  Card,
  Row,
  Col,
  Descriptions,
  Divider,
  Empty,
  Badge,
  Statistic,
  Timeline,
} from 'antd';
import {
  EyeOutlined,
  DeleteOutlined,
  DownloadOutlined,
  FilePdfOutlined,
  FileTextOutlined,
  FileExcelOutlined,
  PlusOutlined,
  CheckCircleOutlined,
  ClockCircleOutlined,
  CloseCircleOutlined,
  BarChartOutlined,
  SecurityScanOutlined,
  BugOutlined,
} from '@ant-design/icons';
import { reportAPI, scanTaskAPI } from '@/api';
import { Report, ReportTemplate, ScanTask } from '@/types';
import dayjs from 'dayjs';

const REPORT_TEMPLATES: ReportTemplate[] = [
  {
    id: 'executive',
    name: '执行摘要报告',
    description: '面向管理层的简明报告，包含关键风险指标和高层建议',
    icon: 'bar-chart',
  },
  {
    id: 'technical',
    name: '技术详细报告',
    description: '包含完整漏洞详情、复现步骤和技术修复方案',
    icon: 'file-text',
  },
  {
    id: 'compliance',
    name: '合规检查报告',
    description: '对照行业标准的安全合规性评估报告',
    icon: 'security-scan',
  },
];

const TEMPLATE_ICONS: Record<string, React.ReactNode> = {
  'bar-chart': <BarChartOutlined className="text-3xl text-blue-500" />,
  'file-text': <FileTextOutlined className="text-3xl text-green-500" />,
  'security-scan': <SecurityScanOutlined className="text-3xl text-purple-500" />,
};

export const Reports = () => {
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(false);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [total, setTotal] = useState(0);

  const [createModalVisible, setCreateModalVisible] = useState(false);
  const [selectedTemplate, setSelectedTemplate] = useState<string | null>(null);
  const [tasks, setTasks] = useState<ScanTask[]>([]);
  const [selectedTask, setSelectedTask] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  const [previewModalVisible, setPreviewModalVisible] = useState(false);
  const [currentReport, setCurrentReport] = useState<Report | null>(null);
  const { message } = App.useApp();

  const fetchReports = useCallback(async () => {
    setLoading(true);
    try {
      const res = await reportAPI.list(page, pageSize);
      setReports(res.data.data);
      setTotal(res.data.total);
    } catch {
      message.error('获取报告列表失败');
    } finally {
      setLoading(false);
    }
  }, [page, pageSize]);

  const fetchTasks = useCallback(async () => {
    try {
      const res = await scanTaskAPI.list(1, 100, 'completed');
      setTasks(res.data.data);
    } catch {
      message.error('获取任务列表失败');
    }
  }, []);

  useEffect(() => {
    fetchReports();
  }, [fetchReports]);

  const handleCreate = () => {
    setSelectedTemplate(null);
    setSelectedTask(null);
    setCreateModalVisible(true);
    fetchTasks();
  };

  const handleGenerateReport = async () => {
    if (!selectedTemplate || !selectedTask) {
      message.warning('请选择报告模板和扫描任务');
      return;
    }
    setCreating(true);
    try {
      await reportAPI.create(selectedTask, selectedTemplate);
      message.success('报告生成任务已创建');
      setCreateModalVisible(false);
      fetchReports();
    } catch {
      message.error('生成报告失败');
    } finally {
      setCreating(false);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await reportAPI.delete(id);
      message.success('删除成功');
      fetchReports();
    } catch {
      message.error('删除失败');
    }
  };

  const handleDownload = async (id: string) => {
    try {
      const res = await reportAPI.download(id);
      const blob = new Blob([res.data], { type: 'application/pdf' });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `report_${id}.pdf`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
      message.success('下载成功');
    } catch {
      message.error('下载失败');
    }
  };

  const handlePreview = (report: Report) => {
    setCurrentReport(report);
    setPreviewModalVisible(true);
  };

  const getStatusTag = (status: Report['status']) => {
    switch (status) {
      case 'completed':
        return <Tag icon={<CheckCircleOutlined />} color="green">已生成</Tag>;
      case 'generating':
        return <Tag icon={<ClockCircleOutlined />} color="blue">生成中</Tag>;
      case 'failed':
        return <Tag icon={<CloseCircleOutlined />} color="red">失败</Tag>;
      default:
        return <Tag>{status}</Tag>;
    }
  };

  const getTemplateName = (templateId: string | null) => {
    if (!templateId) return '-';
    const template = REPORT_TEMPLATES.find((t) => t.id === templateId);
    return template?.name || templateId;
  };

  const columns = [
    {
      title: '任务名称',
      dataIndex: 'task_name',
      key: 'task_name',
      render: (text: string, record: Report) => (
        <div>
          <div className="font-medium">{text}</div>
          <div className="text-xs text-gray-400">{getTemplateName(record.template)}</div>
        </div>
      ),
      ellipsis: true,
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      render: (s: Report['status']) => getStatusTag(s),
      width: 110,
    },
    {
      title: '生成时间',
      dataIndex: 'generated_at',
      key: 'generated_at',
      render: (t: string | null) =>
        t ? (
          <Tooltip title={dayjs(t).format('YYYY-MM-DD HH:mm:ss')}>
            <span>{dayjs(t).format('MM-DD HH:mm')}</span>
          </Tooltip>
        ) : (
          <span className="text-gray-400">-</span>
        ),
      width: 130,
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      key: 'created_at',
      render: (t: string) => dayjs(t).format('YYYY-MM-DD'),
      width: 120,
    },
    {
      title: '操作',
      key: 'action',
      width: 180,
      render: (_: unknown, record: Report) => (
        <Space size="small">
          <Tooltip title="预览">
            <Button
              type="text"
              size="small"
              icon={<EyeOutlined />}
              onClick={() => handlePreview(record)}
              disabled={(record.status as string) !== 'completed'}
            />
          </Tooltip>
          <Tooltip title="下载">
            <Button
              type="text"
              size="small"
              icon={<DownloadOutlined />}
              onClick={() => handleDownload(record.id)}
              disabled={(record.status as string) !== 'completed'}
            />
          </Tooltip>
          <Popconfirm
            title="确认删除"
            description="确定要删除此报告吗？"
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

  // Preview content based on template type
  const renderPreviewContent = () => {
    if (!currentReport) return null;

    const summary = currentReport.summary as Record<string, unknown> || {};
    const statistics = (summary.statistics as Record<string, number>) || {};
    const riskLevel = (summary.risk_level as string) || 'none';
    const target = (summary.target as Record<string, string>) || {};
    const scanTask = (summary.scan_task as Record<string, string>) || {};
    const vulnerabilities = (summary.vulnerabilities as Array<Record<string, unknown>>) || [];

    const total = statistics.total || 0;
    const critical = statistics.critical || 0;
    const high = statistics.high || 0;
    const medium = statistics.medium || 0;
    const low = statistics.low || 0;
    const info = statistics.info || 0;

    return (
      <div>
        {/* Report Header */}
        <div className="text-center mb-8 pb-6 border-b">
          <h2 className="text-2xl font-bold mb-2">
            {getTemplateName(currentReport.template)}
          </h2>
          <p className="text-gray-500">{currentReport.task_name}</p>
          <p className="text-sm text-gray-400 mt-2">
            目标：{target.name || '-'} ({target.url || '-'})
          </p>
          <p className="text-sm text-gray-400 mt-1">
            扫描类型：{scanTask.scan_type || '-'} | 状态：{scanTask.status || '-'}
          </p>
          <p className="text-sm text-gray-400 mt-2">
            生成时间：{currentReport.generated_at ? dayjs(currentReport.generated_at).format('YYYY年MM月DD日 HH:mm') : '-'}
          </p>
        </div>

        {/* Risk Level */}
        <Card className="mb-6">
          <div className="text-center">
            <p className="text-sm text-gray-500 mb-2">综合风险等级</p>
            <Tag color={
              riskLevel === 'critical' ? 'red' :
              riskLevel === 'high' ? 'orange' :
              riskLevel === 'medium' ? 'gold' :
              riskLevel === 'low' ? 'green' : 'default'
            } style={{ fontSize: '16px', padding: '4px 16px' }}>
              {riskLevel === 'critical' ? '严重' :
               riskLevel === 'high' ? '高危' :
               riskLevel === 'medium' ? '中危' :
               riskLevel === 'low' ? '低危' : '无风险'}
            </Tag>
          </div>
        </Card>

        {/* Summary Stats */}
        <Row gutter={[16, 16]} className="mb-6">
          <Col span={6}>
            <Card size="small">
              <Statistic
                title="漏洞总数"
                value={total}
                prefix={<BugOutlined />}
              />
            </Card>
          </Col>
          <Col span={6}>
            <Card size="small">
              <Statistic
                title="严重"
                value={critical}
                valueStyle={{ color: '#ff4d4f' }}
                prefix={<Badge color="red" />}
              />
            </Card>
          </Col>
          <Col span={6}>
            <Card size="small">
              <Statistic
                title="高危"
                value={high}
                valueStyle={{ color: '#faad14' }}
                prefix={<Badge color="orange" />}
              />
            </Card>
          </Col>
          <Col span={6}>
            <Card size="small">
              <Statistic
                title="中危"
                value={medium}
                valueStyle={{ color: '#1890ff' }}
                prefix={<Badge color="blue" />}
              />
            </Card>
          </Col>
        </Row>

        {/* Findings Timeline */}
        <Card title="发现概览" className="mb-6">
          <Timeline
            items={[
              ...(critical > 0 ? [{
                color: 'red' as const,
                children: (
                  <div>
                    <p className="font-medium">严重漏洞发现</p>
                    <p className="text-sm text-gray-500">
                      发现 {critical} 个严重级别漏洞，需要立即处理
                    </p>
                  </div>
                ),
              }] : []),
              ...(high > 0 ? [{
                color: 'orange' as const,
                children: (
                  <div>
                    <p className="font-medium">高危漏洞</p>
                    <p className="text-sm text-gray-500">
                      发现 {high} 个高危漏洞，建议优先修复
                    </p>
                  </div>
                ),
              }] : []),
              ...(medium > 0 ? [{
                color: 'gold' as const,
                children: (
                  <div>
                    <p className="font-medium">中危漏洞</p>
                    <p className="text-sm text-gray-500">
                      发现 {medium} 个中危漏洞
                    </p>
                  </div>
                ),
              }] : []),
              {
                color: 'blue' as const,
                children: (
                  <div>
                    <p className="font-medium">扫描完成</p>
                    <p className="text-sm text-gray-500">
                      扫描任务已完成，共发现 {total} 个漏洞（低危 {low}，信息 {info}）
                    </p>
                  </div>
                ),
              },
            ]}
          />
        </Card>

        {/* Vulnerability List */}
        {vulnerabilities.length > 0 && (
          <Card title={`漏洞详情（${vulnerabilities.length}）`} className="mb-6">
            <div className="space-y-3">
              {vulnerabilities.slice(0, 10).map((vuln, index) => (
                <div key={vuln.id as string || index} className="p-3 border rounded">
                  <div className="flex justify-between items-start">
                    <div>
                      <p className="font-medium">{vuln.title as string}</p>
                      <p className="text-xs text-gray-400">{vuln.plugin_name as string}</p>
                    </div>
                    <Tag color={
                      vuln.severity === 'critical' ? 'red' :
                      vuln.severity === 'high' ? 'orange' :
                      vuln.severity === 'medium' ? 'gold' :
                      vuln.severity === 'low' ? 'green' : 'default'
                    }>
                      {vuln.severity as string}
                    </Tag>
                  </div>
                  {(vuln.description as string) && (
                    <p className="text-sm text-gray-500 mt-2 line-clamp-2">{vuln.description as string}</p>
                  )}
                </div>
              ))}
              {vulnerabilities.length > 10 && (
                <p className="text-center text-sm text-gray-400">仅显示前 10 条，共 {vulnerabilities.length} 条漏洞</p>
              )}
            </div>
          </Card>
        )}

        {/* Recommendations */}
        <Card title="修复建议摘要" className="mb-6">
          <div className="space-y-3">
            {critical > 0 && (
              <div className="flex items-start gap-3 p-3 bg-red-50 dark:bg-red-900/20 rounded">
                <Badge color="red" />
                <div>
                  <p className="font-medium text-red-600">立即处理严重漏洞</p>
                  <p className="text-sm text-gray-500">
                    存在 {critical} 个严重漏洞，可能导致系统被完全控制，请立即修复
                  </p>
                </div>
              </div>
            )}
            {high > 0 && (
              <div className="flex items-start gap-3 p-3 bg-orange-50 dark:bg-orange-900/20 rounded">
                <Badge color="orange" />
                <div>
                  <p className="font-medium text-orange-600">优先修复高危漏洞</p>
                  <p className="text-sm text-gray-500">
                    存在 {high} 个高危漏洞，建议在一周内完成修复
                  </p>
                </div>
              </div>
            )}
            {medium > 0 && (
              <div className="flex items-start gap-3 p-3 bg-blue-50 dark:bg-blue-900/20 rounded">
                <Badge color="blue" />
                <div>
                  <p className="font-medium text-blue-600">计划修复中危漏洞</p>
                  <p className="text-sm text-gray-500">
                    存在 {medium} 个中危漏洞，建议在一个月内完成修复
                  </p>
                </div>
              </div>
            )}
            <div className="flex items-start gap-3 p-3 bg-blue-50 dark:bg-blue-900/20 rounded">
              <Badge color="blue" />
              <div>
                <p className="font-medium text-blue-600">定期扫描建议</p>
                <p className="text-sm text-gray-500">
                  建议每周执行一次全面扫描，及时发现问题
                </p>
              </div>
            </div>
          </div>
        </Card>

        <Divider />

        <div className="text-center text-sm text-gray-400">
          <p>本报告由漏洞扫描平台自动生成</p>
          <p>报告ID：{currentReport.id}</p>
        </div>
      </div>
    );
  };

  return (
    <div className="p-4 md:p-6 animate-fade-in">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center mb-6 gap-4">
        <h2 className="text-xl font-semibold">扫描报告</h2>
        <Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>
          生成报告
        </Button>
      </div>

      {/* Template Cards */}
      <Row gutter={[16, 16]} className="mb-8">
        {REPORT_TEMPLATES.map((template) => (
          <Col xs={24} sm={8} key={template.id}>
            <Card
              hoverable
              className={`h-full transition-all ${selectedTemplate === template.id ? 'ring-2 ring-blue-500' : ''}`}
              onClick={() => setSelectedTemplate(template.id)}
            >
              <div className="text-center">
                <div className="mb-4">{TEMPLATE_ICONS[template.icon]}</div>
                <h3 className="font-medium mb-2">{template.name}</h3>
                <p className="text-sm text-gray-500">{template.description}</p>
              </div>
            </Card>
          </Col>
        ))}
      </Row>

      {/* Reports Table */}
      <h3 className="text-lg font-medium mb-4">历史报告</h3>
      <Table
        dataSource={reports}
        columns={columns}
        rowKey="id"
        loading={loading}
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

      {/* Create Report Modal */}
      <Modal
        title="生成报告"
        open={createModalVisible}
        onCancel={() => setCreateModalVisible(false)}
        onOk={handleGenerateReport}
        confirmLoading={creating}
        okText="生成"
        cancelText="取消"
        width={600}
      >
        <div className="py-4">
          <div className="mb-6">
            <h4 className="font-medium mb-3">1. 选择报告模板</h4>
            <Space wrap>
              {REPORT_TEMPLATES.map((template) => (
                <Button
                  key={template.id}
                  type={selectedTemplate === template.id ? 'primary' : 'default'}
                  onClick={() => setSelectedTemplate(template.id)}
                >
                  {template.name}
                </Button>
              ))}
            </Space>
          </div>

          <div>
            <h4 className="font-medium mb-3">2. 选择扫描任务</h4>
            {tasks.length > 0 ? (
              <Space wrap>
                {tasks.map((task) => (
                  <Button
                    key={task.id}
                    type={selectedTask === task.id ? 'primary' : 'default'}
                    onClick={() => setSelectedTask(task.id)}
                  >
                    {task.name}
                  </Button>
                ))}
              </Space>
            ) : (
              <Empty description="暂无已完成的扫描任务" />
            )}
          </div>
        </div>
      </Modal>

      {/* Preview Modal */}
      <Modal
        title="报告预览"
        open={previewModalVisible}
        onCancel={() => setPreviewModalVisible(false)}
        footer={[
          <Button key="close" onClick={() => setPreviewModalVisible(false)}>
            关闭
          </Button>,
          <Button
            key="download"
            type="primary"
            icon={<DownloadOutlined />}
            onClick={() => currentReport && handleDownload(currentReport.id)}
          >
            下载报告
          </Button>,
        ]}
        width={900}
      >
        {renderPreviewContent()}
      </Modal>
    </div>
  );
};
