import { useState, useEffect, useCallback, useRef } from 'react';
import {
  Table,
  Button,
  Modal,
  Form,
  Input,
  App,
  Tag,
  Popconfirm,
  Upload,
  Tabs,
  Select,
  Space,
  Tooltip,
  Progress,
  Drawer,
  Descriptions,
  Badge,
  Spin,
  Empty,
} from 'antd';
import {
  PlusOutlined,
  EditOutlined,
  DeleteOutlined,
  EyeOutlined,
  PlayCircleOutlined,
  UploadOutlined,
  ImportOutlined,
  GlobalOutlined,
  ClockCircleOutlined,
} from '@ant-design/icons';
import { targetAPI, scanTaskAPI, vulnerabilityAPI } from '@/api';
import { Target, CreateTargetRequest, ScanTask, Vulnerability } from '@/types';
import dayjs from 'dayjs';
import relativeTime from 'dayjs/plugin/relativeTime';
import 'dayjs/locale/zh-cn';

dayjs.extend(relativeTime);
dayjs.locale('zh-cn');

const { TextArea } = Input;
const { Option } = Select;

const SCAN_FREQUENCIES = [
  { value: 'once', label: '仅扫描一次' },
  { value: 'daily', label: '每天' },
  { value: 'weekly', label: '每周' },
  { value: 'monthly', label: '每月' },
];

const isValidURL = (url: string): boolean => {
  const pattern = /^(https?:\/\/)?([\da-z.-]+)\.([a-z.]{2,6})([/\w .-]*)*\/?$/;
  const ipPattern = /^(https?:\/\/)?((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(:\d+)?(\/.*)?$/;
  return pattern.test(url) || ipPattern.test(url);
};

export const Targets = () => {
  const [targets, setTargets] = useState<Target[]>([]);
  const [loading, setLoading] = useState(false);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [total, setTotal] = useState(0);
  const [search, setSearch] = useState('');

  const [modalVisible, setModalVisible] = useState(false);
  const [modalMode, setModalMode] = useState<'create' | 'edit'>('create');
  const [currentTarget, setCurrentTarget] = useState<Target | null>(null);
  const [form] = Form.useForm();

  const [importModalVisible, setImportModalVisible] = useState(false);
  const [importText, setImportText] = useState('');
  const [importLoading, setImportLoading] = useState(false);
  const [importProgress, setImportProgress] = useState(0);

  const [viewingTarget, setViewingTarget] = useState<Target | null>(null);
  const [viewDrawerVisible, setViewDrawerVisible] = useState(false);
  const [relatedTasks, setRelatedTasks] = useState<ScanTask[]>([]);
  const [relatedVulns, setRelatedVulns] = useState<Vulnerability[]>([]);
  const [viewLoading, setViewLoading] = useState(false);

  const searchTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const { message } = App.useApp();

  const fetchTargets = useCallback(async () => {
    setLoading(true);
    try {
      const res = await targetAPI.list(page, pageSize, search || undefined);
      setTargets(res.data.data);
      setTotal(res.data.total);
    } catch {
      message.error('获取目标列表失败');
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, search]);

  useEffect(() => {
    fetchTargets();
  }, [fetchTargets]);

  const handleSearch = (value: string) => {
    if (searchTimeoutRef.current) {
      clearTimeout(searchTimeoutRef.current);
    }
    searchTimeoutRef.current = setTimeout(() => {
      setSearch(value);
      setPage(1);
    }, 300);
  };

  const handleCreate = () => {
    setModalMode('create');
    setCurrentTarget(null);
    form.resetFields();
    setModalVisible(true);
  };

  const handleEdit = (target: Target) => {
    setModalMode('edit');
    setCurrentTarget(target);
    form.setFieldsValue({
      name: target.name,
      url: target.url,
      description: target.description || '',
      scan_frequency: target.scan_frequency || 'once',
    });
    setModalVisible(true);
  };

  const handleDelete = async (id: string) => {
    try {
      await targetAPI.delete(id);
      message.success('删除成功');
      fetchTargets();
    } catch {
      message.error('删除失败');
    }
  };

  const handleSubmit = async (values: CreateTargetRequest) => {
    try {
      if (modalMode === 'edit' && currentTarget) {
        await targetAPI.update(currentTarget.id, values);
        message.success('更新成功');
      } else {
        await targetAPI.create(values);
        message.success('创建成功');
      }
      setModalVisible(false);
      fetchTargets();
    } catch {
      message.error(modalMode === 'edit' ? '更新失败' : '创建失败');
    }
  };

  const handleStartScan = async (target: Target) => {
    try {
      await scanTaskAPI.create({
        target_id: target.id,
        scan_type: 'full',
        priority: 'medium',
        plugins: ['directory_scanner', 'sql_injection_scanner', 'xss_scanner', 'weak_password_scanner'],
      });
      message.success('扫描任务已创建');
    } catch {
      message.error('创建扫描任务失败');
    }
  };

  const handleImport = async () => {
    if (!importText.trim()) {
      message.warning('请输入要导入的目标');
      return;
    }

    setImportLoading(true);
    setImportProgress(0);

    const lines = importText.split('\n').filter((line) => line.trim());
    const validTargets: CreateTargetRequest[] = [];
    const invalidLines: string[] = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      const parts = line.split(/[,\s]+/);
      const url = parts[0];
      const name = parts[1] || url;

      if (isValidURL(url)) {
        validTargets.push({ name, url });
      } else {
        invalidLines.push(line);
      }

      setImportProgress(Math.round(((i + 1) / lines.length) * 100));

      // Simulate processing delay for UX
      if (i % 10 === 0) {
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
    }

    if (validTargets.length > 0) {
      try {
        const res = await targetAPI.batchCreate(validTargets);
        message.success(`成功导入 ${res.data.created} 个目标${res.data.failed > 0 ? `，失败 ${res.data.failed} 个` : ''}`);
        if (invalidLines.length > 0) {
          message.warning(`以下 ${invalidLines.length} 行格式无效：\n${invalidLines.slice(0, 5).join('\n')}${invalidLines.length > 5 ? '\n...' : ''}`);
        }
        setImportModalVisible(false);
        setImportText('');
        fetchTargets();
      } catch {
        message.error('批量导入失败');
      }
    } else {
      message.error('未找到有效的目标URL');
    }

    setImportLoading(false);
  };

  const getStatusTag = (status: string) => {
    switch (status) {
      case 'active':
        return <Tag color="green">正常</Tag>;
      case 'inactive':
        return <Tag color="gray">停用</Tag>;
      case 'scanning':
        return <Tag color="blue">扫描中</Tag>;
      case 'error':
        return <Tag color="red">错误</Tag>;
      default:
        return <Tag>{status}</Tag>;
    }
  };

  const getVulnSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'red';
      case 'high': return 'orange';
      case 'medium': return 'yellow';
      case 'low': return 'blue';
      case 'info': return 'default';
      default: return 'default';
    }
  };

  const getVulnSeverityLabel = (severity: string) => {
    const map: Record<string, string> = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息' };
    return map[severity] || severity;
  };

  const handleView = async (target: Target) => {
    setViewingTarget(target);
    setViewDrawerVisible(true);
    setViewLoading(true);
    setRelatedTasks([]);
    setRelatedVulns([]);
    try {
      const [tasksRes, vulnsRes] = await Promise.all([
        scanTaskAPI.list(1, 100),
        vulnerabilityAPI.list(1, 100),
      ]);
      // 过滤出与当前目标关联的扫描任务（通过 target_ids 匹配）
      setRelatedTasks(tasksRes.data.data.filter((t) => t.target_ids?.includes(target.id)));
      // 过滤出与当前目标关联的漏洞
      setRelatedVulns(vulnsRes.data.data.filter((v) => v.target_id === target.id));
    } catch {
      message.error('获取关联数据失败');
    } finally {
      setViewLoading(false);
    }
  };

  const columns = [
    {
      title: '名称',
      dataIndex: 'name',
      key: 'name',
      render: (text: string, record: Target) => (
        <div>
          <div className="font-medium">{text}</div>
          <div className="text-xs text-gray-400">{record.url}</div>
        </div>
      ),
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
      title: '最后扫描时间',
      dataIndex: 'last_scan_at',
      key: 'last_scan_at',
      render: (t: string | null) =>
        t ? (
          <Tooltip title={dayjs(t).format('YYYY-MM-DD HH:mm:ss')}>
            <span className="text-sm">{dayjs(t).fromNow()}</span>
          </Tooltip>
        ) : (
          <span className="text-gray-400 text-sm">未扫描</span>
        ),
      width: 130,
    },
    {
      title: '扫描频率',
      dataIndex: 'scan_frequency',
      key: 'scan_frequency',
      render: (f: string | null) => {
        const freq = SCAN_FREQUENCIES.find((item) => item.value === f);
        return <span className="text-sm">{freq?.label || '仅一次'}</span>;
      },
      width: 110,
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
      render: (_: unknown, record: Target) => (
        <Space size="small">
          <Tooltip title="查看">
            <Button type="text" size="small" icon={<EyeOutlined />} onClick={() => handleView(record)} />
          </Tooltip>
          <Tooltip title="编辑">
            <Button type="text" size="small" icon={<EditOutlined />} onClick={() => handleEdit(record)} />
          </Tooltip>
          <Tooltip title="扫描">
            <Button
              type="text"
              size="small"
              icon={<PlayCircleOutlined />}
              onClick={() => handleStartScan(record)}
              disabled={record.status === 'scanning'}
            />
          </Tooltip>
          <Popconfirm
            title="确认删除"
            description={`确定要删除目标 "${record.name}" 吗？`}
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

  return (
    <div className="p-4 md:p-6 animate-fade-in">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center mb-6 gap-4">
        <h2 className="text-xl font-semibold">目标管理</h2>
        <Space wrap>
          <Input.Search
            placeholder="搜索目标名称或URL"
            allowClear
            onSearch={handleSearch}
            onChange={(e) => handleSearch(e.target.value)}
            style={{ width: 240 }}
            size="middle"
          />
          <Button icon={<ImportOutlined />} onClick={() => setImportModalVisible(true)}>
            批量导入
          </Button>
          <Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>
            添加目标
          </Button>
        </Space>
      </div>

      <Table
        dataSource={targets}
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

      {/* Create/Edit Modal */}
      <Modal
        title={modalMode === 'edit' ? '编辑目标' : '添加目标'}
        open={modalVisible}
        onCancel={() => setModalVisible(false)}
        footer={null}
        destroyOnHidden
      >
        <Form form={form} layout="vertical" onFinish={handleSubmit}>
          <Form.Item
            name="name"
            label="目标名称"
            rules={[{ required: true, message: '请输入目标名称' }]}
          >
            <Input prefix={<GlobalOutlined />} placeholder="如：官网首页" />
          </Form.Item>
          <Form.Item
            name="url"
            label="URL / IP"
            rules={[
              { required: true, message: '请输入目标URL或IP' },
              {
                validator: (_, value) => {
                  if (!value || isValidURL(value)) {
                    return Promise.resolve();
                  }
                  return Promise.reject(new Error('请输入有效的URL或IP地址'));
                },
              },
            ]}
          >
            <Input placeholder="如 http://example.com 或 192.168.1.1" />
          </Form.Item>
          <Form.Item name="scan_frequency" label="扫描频率" initialValue="once">
            <Select placeholder="选择扫描频率">
              {SCAN_FREQUENCIES.map((f) => (
                <Option key={f.value} value={f.value}>
                  {f.label}
                </Option>
              ))}
            </Select>
          </Form.Item>
          <Form.Item name="description" label="描述">
            <TextArea placeholder="可选：输入目标描述" rows={3} maxLength={500} showCount />
          </Form.Item>
          <Form.Item className="mb-0 flex justify-end">
            <Space>
              <Button onClick={() => setModalVisible(false)}>取消</Button>
              <Button type="primary" htmlType="submit">
                {modalMode === 'edit' ? '保存' : '创建'}
              </Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>

      {/* Import Modal */}
      <Modal
        title="批量导入目标"
        open={importModalVisible}
        onCancel={() => {
          if (!importLoading) {
            setImportModalVisible(false);
            setImportText('');
            setImportProgress(0);
          }
        }}
        footer={null}
        destroyOnHidden
        width={600}
      >
        <Tabs
          items={[
            {
              key: 'text',
              label: '文本导入',
              children: (
                <div>
                  <p className="text-gray-500 mb-4 text-sm">
                    每行输入一个目标，格式：URL [名称]（名称可选，用空格或逗号分隔）
                    <br />
                    示例：
                    <br />
                    <code className="bg-gray-100 px-1 rounded">https://example.com 示例网站</code>
                    <br />
                    <code className="bg-gray-100 px-1 rounded">192.168.1.1 内网服务器</code>
                  </p>
                  <TextArea
                    rows={8}
                    placeholder="输入目标列表..."
                    value={importText}
                    onChange={(e) => setImportText(e.target.value)}
                    disabled={importLoading}
                  />
                  {importLoading && (
                    <div className="mt-4">
                      <Progress percent={importProgress} status="active" />
                      <p className="text-sm text-gray-500 mt-2">正在处理...</p>
                    </div>
                  )}
                  <div className="flex justify-end mt-4 gap-2">
                    <Button onClick={() => setImportModalVisible(false)} disabled={importLoading}>
                      取消
                    </Button>
                    <Button type="primary" onClick={handleImport} loading={importLoading} icon={<UploadOutlined />}>
                      导入
                    </Button>
                  </div>
                </div>
              ),
            },
            {
              key: 'file',
              label: '文件导入',
              children: (
                <div className="py-8">
                  <Upload.Dragger
                    accept=".txt,.csv,.xlsx,.xls"
                    multiple={false}
                    beforeUpload={(file) => {
                      const reader = new FileReader();
                      reader.onload = (e) => {
                        const text = e.target?.result as string;
                        setImportText(text);
                        message.success(`已读取文件：${file.name}`);
                      };
                      reader.readAsText(file);
                      return false;
                    }}
                    showUploadList={false}
                  >
                    <p className="text-4xl mb-4">
                      <UploadOutlined />
                    </p>
                    <p className="text-lg mb-2">点击或拖拽文件至此处</p>
                    <p className="text-gray-400 text-sm">支持 .txt, .csv, .xlsx, .xls 格式</p>
                  </Upload.Dragger>
                </div>
              ),
            },
          ]}
        />
      </Modal>

      {/* View Detail Drawer */}
      <Drawer
        title="目标详情"
        width={600}
        open={viewDrawerVisible}
        onClose={() => {
          setViewDrawerVisible(false);
          setViewingTarget(null);
        }}
        destroyOnHidden
      >
        {viewingTarget && (
          <Spin spinning={viewLoading}>
            <Descriptions bordered column={1} size="small" className="mb-6">
              <Descriptions.Item label="名称">{viewingTarget.name}</Descriptions.Item>
              <Descriptions.Item label="URL">
                <a href={viewingTarget.url} target="_blank" rel="noopener noreferrer">
                  {viewingTarget.url}
                </a>
              </Descriptions.Item>
              <Descriptions.Item label="描述">
                {viewingTarget.description || <span className="text-gray-400">无描述</span>}
              </Descriptions.Item>
              <Descriptions.Item label="状态">{getStatusTag(viewingTarget.status)}</Descriptions.Item>
              <Descriptions.Item label="扫描频率">
                {SCAN_FREQUENCIES.find((f) => f.value === viewingTarget.scan_frequency)?.label || '仅一次'}
              </Descriptions.Item>
              <Descriptions.Item label="创建时间">
                {dayjs(viewingTarget.created_at).format('YYYY-MM-DD HH:mm:ss')}
              </Descriptions.Item>
              <Descriptions.Item label="更新时间">
                {dayjs(viewingTarget.updated_at).format('YYYY-MM-DD HH:mm:ss')}
              </Descriptions.Item>
              <Descriptions.Item label="最后扫描时间">
                {viewingTarget.last_scan_at
                  ? dayjs(viewingTarget.last_scan_at).format('YYYY-MM-DD HH:mm:ss')
                  : <span className="text-gray-400">未扫描</span>}
              </Descriptions.Item>
            </Descriptions>

            {/* 漏洞统计 */}
            <div className="mb-6">
              <h4 className="font-medium mb-3">漏洞统计</h4>
              {relatedVulns.length > 0 ? (
                <>
                  <div className="flex gap-4 mb-3">
                    {(['critical', 'high', 'medium', 'low', 'info'] as const).map((sev) => {
                      const count = relatedVulns.filter((v) => v.severity === sev).length;
                      if (count === 0) return null;
                      return (
                        <Badge
                          key={sev}
                          count={count}
                          style={{ backgroundColor: getVulnSeverityColor(sev) === 'default' ? '#999' : undefined }}
                          color={getVulnSeverityColor(sev) !== 'default' ? getVulnSeverityColor(sev) : undefined}
                        >
                          <Tag color={getVulnSeverityColor(sev)}>{getVulnSeverityLabel(sev)}</Tag>
                        </Badge>
                      );
                    })}
                  </div>
                  <div className="max-h-48 overflow-auto">
                    {relatedVulns.slice(0, 10).map((vuln) => (
                      <div key={vuln.id} className="flex items-center justify-between py-1 border-b border-gray-100 last:border-0">
                        <div className="flex-1 min-w-0">
                          <div className="text-sm font-medium truncate">{vuln.title}</div>
                          <div className="text-xs text-gray-400 truncate">
                            {vuln.plugin_name}{vuln.cve ? ` | ${vuln.cve}` : ''}
                          </div>
                        </div>
                        <Tag color={getVulnSeverityColor(vuln.severity)} className="ml-2 flex-shrink-0">
                          {getVulnSeverityLabel(vuln.severity)}
                        </Tag>
                      </div>
                    ))}
                    {relatedVulns.length > 10 && (
                      <div className="text-xs text-gray-400 text-center py-1">
                        还有 {relatedVulns.length - 10} 个漏洞...
                      </div>
                    )}
                  </div>
                </>
              ) : (
                <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无漏洞数据" />
              )}
            </div>

            {/* 关联的扫描任务 */}
            <div>
              <h4 className="font-medium mb-3">关联扫描任务</h4>
              {relatedTasks.length > 0 ? (
                <div className="max-h-64 overflow-auto">
                  {relatedTasks.map((task) => (
                    <div key={task.id} className="flex items-center justify-between py-2 border-b border-gray-100 last:border-0">
                      <div className="flex-1 min-w-0">
                        <div className="text-sm font-medium truncate">{task.name}</div>
                        <div className="text-xs text-gray-400">
                          {dayjs(task.created_at).format('YYYY-MM-DD HH:mm')}
                        </div>
                      </div>
                      <div className="flex items-center gap-2 flex-shrink-0 ml-2">
                        <Progress
                          percent={task.progress}
                          size="small"
                          style={{ width: 80 }}
                          status={
                            task.status === 'failed' ? 'exception'
                              : task.status === 'completed' ? 'success'
                              : task.status === 'running' || task.status === 'scanning' ? 'active'
                              : 'normal'
                          }
                        />
                        <Tag
                          color={
                            task.status === 'running' || task.status === 'scanning' ? 'blue'
                              : task.status === 'completed' ? 'green'
                              : task.status === 'failed' ? 'red'
                              : task.status === 'paused' ? 'orange'
                              : 'default'
                          }
                        >
                          {task.status === 'running' || task.status === 'scanning' ? '扫描中'
                            : task.status === 'completed' ? '已完成'
                            : task.status === 'failed' ? '失败'
                            : task.status === 'paused' ? '已暂停'
                            : task.status === 'pending' ? '等待中'
                            : task.status === 'queued' ? '排队中'
                            : task.status === 'cancelled' ? '已取消'
                            : task.status}
                        </Tag>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无关联扫描任务" />
              )}
            </div>
          </Spin>
        )}
      </Drawer>
    </div>
  );
};
