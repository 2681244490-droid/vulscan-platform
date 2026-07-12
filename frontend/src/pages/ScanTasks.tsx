import { useState, useEffect, useCallback, useRef } from 'react';
import {
  Table,
  Button,
  Modal,
  Form,
  Select,
  App,
  Tag,
  Progress,
  Steps,
  Space,
  Tooltip,
  Popconfirm,
  Input,
  InputNumber,
  Slider,
  Badge,
  Card,
  List,
  Checkbox,
  Divider,
  Empty,
} from 'antd';
import {
  PlusOutlined,
  ReloadOutlined,
  PauseCircleOutlined,
  PlayCircleOutlined,
  StopOutlined,
  DeleteOutlined,
  EyeOutlined,
  LoadingOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
  ClockCircleOutlined,
  AlertOutlined,
  CodeOutlined,
  SettingOutlined,
  AimOutlined,
} from '@ant-design/icons';
import { scanTaskAPI, targetAPI } from '@/api';
import { ScanTask, CreateScanTaskRequest, Target, ScanProgress } from '@/types';
import { useScanProgress } from '@/hooks/useScanProgress';
import dayjs from 'dayjs';

const { Step } = Steps;
const { Option } = Select;

const SCAN_PLUGINS = [
  { category: 'Web漏洞', plugins: ['SQL注入', 'XSS跨站脚本', 'CSRF跨站请求伪造', '文件上传漏洞', '命令注入'] },
  { category: '信息泄露', plugins: ['敏感文件泄露', '目录遍历', '源代码泄露', '配置信息泄露'] },
  { category: '服务安全', plugins: ['弱口令检测', '未授权访问', '端口扫描', '服务指纹识别'] },
  { category: 'SSL/TLS', plugins: ['SSL配置检测', '证书过期检测', '弱加密算法'] },
];

export const ScanTasks = () => {
  const [tasks, setTasks] = useState<ScanTask[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [loading, setLoading] = useState(false);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [total, setTotal] = useState(0);
  const [statusFilter, setStatusFilter] = useState<string | undefined>();

  const [modalVisible, setModalVisible] = useState(false);
  const [currentStep, setCurrentStep] = useState(0);
  const [wizardForm] = Form.useForm();
  const [selectedTargets, setSelectedTargets] = useState<string[]>([]);
  const [selectedPlugins, setSelectedPlugins] = useState<string[]>([]);
  const [taskName, setTaskName] = useState('');
  const [targetSearch, setTargetSearch] = useState('');

  const [detailModalVisible, setDetailModalVisible] = useState(false);
  const [currentTask, setCurrentTask] = useState<ScanTask | null>(null);
  const [activeProgressTask, setActiveProgressTask] = useState<string | undefined>();

  const [pollingInterval, setPollingInterval] = useState<ReturnType<typeof setInterval> | null>(null);
  const { message } = App.useApp();

  const fetchTasks = useCallback(async () => {
    setLoading(true);
    try {
      const res = await scanTaskAPI.list(page, pageSize, statusFilter);
      setTasks(res.data.data);
      setTotal(res.data.total);
    } catch {
      message.error('获取任务列表失败');
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, statusFilter]);

  const fetchTargets = useCallback(async () => {
    try {
      const res = await targetAPI.list(1, 1000);
      setTargets(res.data.data);
    } catch {
      message.error('获取目标列表失败');
    }
  }, []);

  useEffect(() => {
    fetchTasks();
  }, [fetchTasks]);

  // Auto-refresh for running tasks
  useEffect(() => {
    const interval = setInterval(() => {
      const hasRunning = tasks.some((t) => t.status === 'running' || t.status === 'scanning' || t.status === 'pending' || t.status === 'queued');
      if (hasRunning) {
        fetchTasks();
      }
    }, 3000);
    setPollingInterval(interval);
    return () => clearInterval(interval);
  }, [tasks, fetchTasks]);

  const { progress: liveProgress } = useScanProgress({
    taskId: activeProgressTask,
    enabled: !!activeProgressTask,
    onProgress: (p: ScanProgress) => {
      setTasks((prev) =>
        prev.map((t) =>
          t.id === p.task_id
            ? { ...t, progress: p.progress, status: p.status }
            : t
        )
      );
    },
    onComplete: () => {
      fetchTasks();
      setActiveProgressTask(undefined);
    },
  });

  const handleCreate = () => {
    wizardForm.resetFields();
    setCurrentStep(0);
    setSelectedTargets([]);
    setSelectedPlugins([]);
    setTaskName('');
    setTargetSearch('');
    setModalVisible(true);
    fetchTargets();
  };

  const handlePause = async (id: string) => {
    try {
      await scanTaskAPI.pause(id);
      message.success('任务已暂停');
      fetchTasks();
    } catch {
      message.error('暂停任务失败');
    }
  };

  const handleResume = async (id: string) => {
    try {
      await scanTaskAPI.resume(id);
      message.success('任务已恢复');
      fetchTasks();
    } catch {
      message.error('恢复任务失败');
    }
  };

  const handleCancel = async (id: string) => {
    try {
      await scanTaskAPI.cancel(id);
      message.success('任务已终止');
      fetchTasks();
    } catch {
      message.error('终止任务失败');
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await scanTaskAPI.delete(id);
      message.success('删除成功');
      fetchTasks();
    } catch {
      message.error('删除失败');
    }
  };

  const handleViewDetail = (task: ScanTask) => {
    setCurrentTask(task);
    setDetailModalVisible(true);
    if (task.status === 'running' || task.status === 'scanning') {
      setActiveProgressTask(task.id);
    }
  };

  const handleWizardSubmit = async () => {
    try {
      const values = await wizardForm.validateFields();
      // 为每个目标创建扫描任务
      for (const targetId of selectedTargets) {
        const request: CreateScanTaskRequest = {
          target_id: targetId,
          scan_type: values.scan_type,
          priority: values.priority,
          concurrency: values.concurrency,
          plugins: selectedPlugins.length > 0 ? selectedPlugins : undefined,
        };
        await scanTaskAPI.create(request);
      }
      message.success(`已创建 ${selectedTargets.length} 个扫描任务`);
      setModalVisible(false);
      fetchTasks();
    } catch {
      message.error('创建任务失败');
    }
  };

  const nextStep = async () => {
    try {
      if (currentStep === 0) {
        if (selectedTargets.length === 0) {
          message.warning('请至少选择一个目标');
          return;
        }
      }
      if (currentStep === 2) {
        await wizardForm.validateFields();
      }
      if (currentStep < 2) {
        setCurrentStep(currentStep + 1);
      } else {
        await handleWizardSubmit();
      }
    } catch {
      // validation error
    }
  };

  const prevStep = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1);
    }
  };

  const getStatusTag = (status: string) => {
    switch (status) {
      case 'running':
      case 'scanning':
        return <Tag icon={<LoadingOutlined />} color="blue">扫描中</Tag>;
      case 'completed':
        return <Tag icon={<CheckCircleOutlined />} color="green">已完成</Tag>;
      case 'failed':
        return <Tag icon={<CloseCircleOutlined />} color="red">失败</Tag>;
      case 'pending':
        return <Tag icon={<ClockCircleOutlined />} color="yellow">等待中</Tag>;
      case 'queued':
        return <Tag icon={<ClockCircleOutlined />} color="cyan">排队中</Tag>;
      case 'paused':
        return <Tag icon={<PauseCircleOutlined />} color="orange">已暂停</Tag>;
      case 'cancelled':
        return <Tag icon={<StopOutlined />}>已取消</Tag>;
      default:
        return <Tag>{status}</Tag>;
    }
  };

  const getPriorityTag = (priority: string) => {
    switch (priority) {
      case 'critical':
        return <Badge color="red" text="紧急" />;
      case 'high':
        return <Badge color="orange" text="高" />;
      case 'medium':
        return <Badge color="yellow" text="中" />;
      case 'low':
        return <Badge color="blue" text="低" />;
      default:
        return <Badge text={priority} />;
    }
  };

  const columns = [
    {
      title: '任务名称',
      dataIndex: 'name',
      key: 'name',
      render: (text: string, record: ScanTask) => (
        <div>
          <div className="font-medium">{text}</div>
          <div className="text-xs text-gray-400">{record.target_count} 个目标</div>
        </div>
      ),
      ellipsis: true,
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      render: (s: string) => getStatusTag(s),
      width: 110,
      filters: [
        { text: '等待中', value: 'pending' },
        { text: '运行中', value: 'running' },
        { text: '已暂停', value: 'paused' },
        { text: '已完成', value: 'completed' },
        { text: '失败', value: 'failed' },
        { text: '已取消', value: 'cancelled' },
      ],
      onFilter: (value: React.Key | boolean, record: ScanTask) => record.status === value,
    },
    {
      title: '进度',
      dataIndex: 'progress',
      key: 'progress',
      render: (p: number, record: ScanTask) => (
        <div className="w-32">
          <Progress
            percent={p}
            size="small"
            status={record.status === 'failed' ? 'exception' : record.status === 'completed' ? 'success' : 'active'}
          />
        </div>
      ),
      width: 150,
    },
    {
      title: '扫描类型',
      dataIndex: 'scan_type',
      key: 'scan_type',
      render: (s: string) => {
        const map: Record<string, string> = { full: '全面', quick: '快速', custom: '自定义' };
        return <Tag>{map[s] || s}</Tag>;
      },
      width: 100,
    },
    {
      title: '优先级',
      dataIndex: 'priority',
      key: 'priority',
      render: (p: string) => getPriorityTag(p),
      width: 90,
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      key: 'created_at',
      render: (t: string) => dayjs(t).format('MM-DD HH:mm'),
      width: 130,
    },
    {
      title: '操作',
      key: 'action',
      width: 220,
      render: (_: unknown, record: ScanTask) => (
        <Space size="small">
          <Tooltip title="查看详情">
            <Button type="text" size="small" icon={<EyeOutlined />} onClick={() => handleViewDetail(record)} />
          </Tooltip>
          {(record.status === 'running' || record.status === 'scanning') && (
            <Tooltip title="暂停">
              <Button type="text" size="small" icon={<PauseCircleOutlined />} onClick={() => handlePause(record.id)} />
            </Tooltip>
          )}
          {record.status === 'paused' && (
            <Tooltip title="继续">
              <Button type="text" size="small" icon={<PlayCircleOutlined />} onClick={() => handleResume(record.id)} />
            </Tooltip>
          )}
          {(record.status === 'running' || record.status === 'scanning' || record.status === 'pending' || record.status === 'queued' || record.status === 'paused') && (
            <Popconfirm
              title="确认终止"
              description="确定要终止该任务吗？此操作不可撤销。"
              onConfirm={() => handleCancel(record.id)}
              okText="终止"
              cancelText="取消"
              okButtonProps={{ danger: true }}
            >
              <Tooltip title="终止">
                <Button type="text" danger size="small" icon={<StopOutlined />} />
              </Tooltip>
            </Popconfirm>
          )}
          <Popconfirm
            title="确认删除"
            description="确定要删除该任务吗？"
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

  const renderWizardStep = () => {
    switch (currentStep) {
      case 0:
        return (
          <div className="py-4">
            <div className="mb-4">
              <Input.Search
                placeholder="搜索目标..."
                value={targetSearch}
                onChange={(e) => setTargetSearch(e.target.value)}
                onSearch={(v) => setTargetSearch(v)}
                allowClear
                className="mb-4"
              />
              <div className="mb-2 text-sm text-gray-500">
                已选择 {selectedTargets.length} 个目标
              </div>
            </div>
            <List
              bordered
              dataSource={targets.filter(t =>
                !targetSearch ||
                t.name.toLowerCase().includes(targetSearch.toLowerCase()) ||
                t.url.toLowerCase().includes(targetSearch.toLowerCase())
              )}
              renderItem={(target) => (
                <List.Item
                  actions={[
                    <Checkbox
                      checked={selectedTargets.includes(target.id)}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setSelectedTargets([...selectedTargets, target.id]);
                        } else {
                          setSelectedTargets(selectedTargets.filter((id) => id !== target.id));
                        }
                      }}
                    />,
                  ]}
                >
                  <List.Item.Meta
                    title={target.name}
                    description={target.url}
                  />
                </List.Item>
              )}
              style={{ maxHeight: '320px', overflow: 'auto' }}
            />
          </div>
        );
      case 1:
        return (
          <div className="py-4">
            <div className="mb-4 text-sm text-gray-500">
              选择要启用的扫描插件（不选则使用默认配置）
            </div>
            {SCAN_PLUGINS.map((group) => (
              <Card key={group.category} size="small" title={group.category} className="mb-3">
                <Checkbox.Group
                  value={selectedPlugins}
                  onChange={(values) => setSelectedPlugins(values as string[])}
                >
                  <Space wrap>
                    {group.plugins.map((plugin) => (
                      <Checkbox key={plugin} value={plugin}>
                        {plugin}
                      </Checkbox>
                    ))}
                  </Space>
                </Checkbox.Group>
              </Card>
            ))}
          </div>
        );
      case 2:
        return (
          <div className="py-4">
            <Form form={wizardForm} layout="vertical">
              <Form.Item
                name="task_name"
                label="任务名称"
                rules={[{ required: true, message: '请输入任务名称' }]}
              >
                <Input
                  placeholder="输入任务名称"
                  value={taskName}
                  onChange={(e) => setTaskName(e.target.value)}
                  prefix={<CodeOutlined />}
                />
              </Form.Item>
              <Form.Item
                name="scan_type"
                label="扫描类型"
                initialValue="full"
                rules={[{ required: true }]}
              >
                <Select placeholder="选择扫描类型">
                  <Option value="full">
                    <div className="flex items-center gap-2">
                      <AimOutlined /> 全面扫描（推荐）
                    </div>
                  </Option>
                  <Option value="quick">
                    <div className="flex items-center gap-2">
                      <AlertOutlined /> 快速扫描
                    </div>
                  </Option>
                  <Option value="custom">
                    <div className="flex items-center gap-2">
                      <SettingOutlined /> 自定义扫描
                    </div>
                  </Option>
                </Select>
              </Form.Item>
              <Form.Item
                name="priority"
                label="优先级"
                initialValue="medium"
                rules={[{ required: true }]}
              >
                <Select placeholder="选择优先级">
                  <Option value="critical">紧急</Option>
                  <Option value="high">高</Option>
                  <Option value="medium">中</Option>
                  <Option value="low">低</Option>
                </Select>
              </Form.Item>
              <Form.Item
                name="concurrency"
                label="并发数"
                initialValue={5}
                extra="同时扫描的目标数量（1-20）"
              >
                <Slider min={1} max={20} marks={{ 1: '1', 5: '5', 10: '10', 15: '15', 20: '20' }} />
              </Form.Item>
            </Form>
            <Divider />
            <div className="bg-gray-50 dark:bg-gray-800 p-4 rounded-lg">
              <h4 className="font-medium mb-2">任务摘要</h4>
              <p className="text-sm text-gray-500">目标数量：{selectedTargets.length}</p>
              <p className="text-sm text-gray-500">扫描插件：{selectedPlugins.length > 0 ? `${selectedPlugins.length} 个` : '默认配置'}</p>
            </div>
          </div>
        );
      default:
        return null;
    }
  };

  return (
    <div className="p-4 md:p-6 animate-fade-in">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center mb-6 gap-4">
        <h2 className="text-xl font-semibold">扫描任务</h2>
        <Space wrap>
          <Select
            placeholder="状态筛选"
            allowClear
            style={{ width: 120 }}
            onChange={(value) => {
              setStatusFilter(value);
              setPage(1);
            }}
            options={[
              { value: 'pending', label: '等待中' },
              { value: 'running', label: '运行中' },
              { value: 'paused', label: '已暂停' },
              { value: 'completed', label: '已完成' },
              { value: 'failed', label: '失败' },
              { value: 'cancelled', label: '已取消' },
            ]}
          />
          <Button icon={<ReloadOutlined />} onClick={fetchTasks} loading={loading}>
            刷新
          </Button>
          <Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>
            创建任务
          </Button>
        </Space>
      </div>

      <Table
        dataSource={tasks}
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

      {/* Create Task Wizard Modal */}
      <Modal
        title="创建扫描任务"
        open={modalVisible}
        onCancel={() => setModalVisible(false)}
        footer={null}
        destroyOnHidden
        width={700}
      >
        <Steps current={currentStep} className="mb-6">
          <Step title="选择目标" icon={<AimOutlined />} />
          <Step title="选择规则" icon={<SettingOutlined />} />
          <Step title="设置参数" icon={<CodeOutlined />} />
        </Steps>

        {renderWizardStep()}

        <div className="flex justify-between mt-6">
          <Button disabled={currentStep === 0} onClick={prevStep}>
            上一步
          </Button>
          <Space>
            <Button onClick={() => setModalVisible(false)}>取消</Button>
            <Button type="primary" onClick={nextStep}>
              {currentStep === 2 ? '创建任务' : '下一步'}
            </Button>
          </Space>
        </div>
      </Modal>

      {/* Task Detail Modal */}
      <Modal
        title="任务详情"
        open={detailModalVisible}
        onCancel={() => {
          setDetailModalVisible(false);
          setActiveProgressTask(undefined);
        }}
        footer={null}
        width={600}
      >
        {currentTask && (
          <div>
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-lg font-medium">{currentTask.name}</h3>
              {getStatusTag(currentTask.status)}
            </div>

            {(currentTask.status === 'running' || currentTask.status === 'scanning') && liveProgress && (
              <Card size="small" className="mb-4 bg-blue-50 dark:bg-blue-900/20">
                <div className="mb-2">
                  <Progress percent={liveProgress.progress} status="active" />
                </div>
                <div className="text-sm text-gray-500">
                  <p>当前目标：{liveProgress.current_target}</p>
                  <p>状态消息：{liveProgress.message}</p>
                  <p>发现漏洞：{liveProgress.vulnerabilities_found} 个</p>
                </div>
              </Card>
            )}

            <div className="grid grid-cols-2 gap-4 mb-4">
              <div>
                <p className="text-gray-400 text-sm">扫描类型</p>
                <p className="font-medium">{currentTask.scan_type === 'full' ? '全面扫描' : currentTask.scan_type === 'quick' ? '快速扫描' : '自定义扫描'}</p>
              </div>
              <div>
                <p className="text-gray-400 text-sm">优先级</p>
                <p className="font-medium">{getPriorityTag(currentTask.priority)}</p>
              </div>
              <div>
                <p className="text-gray-400 text-sm">目标数量</p>
                <p className="font-medium">{currentTask.target_count}</p>
              </div>
              <div>
                <p className="text-gray-400 text-sm">并发数</p>
                <p className="font-medium">{currentTask.concurrency || 1}</p>
              </div>
              <div>
                <p className="text-gray-400 text-sm">开始时间</p>
                <p className="font-medium">{currentTask.started_at ? dayjs(currentTask.started_at).format('YYYY-MM-DD HH:mm:ss') : '-'}</p>
              </div>
              <div>
                <p className="text-gray-400 text-sm">完成时间</p>
                <p className="font-medium">{currentTask.completed_at ? dayjs(currentTask.completed_at).format('YYYY-MM-DD HH:mm:ss') : '-'}</p>
              </div>
            </div>

            {(currentTask.status === 'running' || currentTask.status === 'scanning') && (
              <div className="flex justify-center gap-4 mt-4">
                <Button icon={<PauseCircleOutlined />} onClick={() => handlePause(currentTask.id)}>
                  暂停
                </Button>
                <Button danger icon={<StopOutlined />} onClick={() => handleCancel(currentTask.id)}>
                  终止
                </Button>
              </div>
            )}
          </div>
        )}
      </Modal>
    </div>
  );
};
