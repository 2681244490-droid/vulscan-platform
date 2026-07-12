import React, { Component, ErrorInfo, ReactNode } from 'react';
import { Result, Button } from 'antd';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Error Boundary caught error:', error, errorInfo);
  }

  componentDidMount() {
    const handleUncaughtError = (event: ErrorEvent) => {
      event.preventDefault();
      this.setState({ hasError: true, error: event.error });
    };

    const handlePromiseRejection = (event: PromiseRejectionEvent) => {
      event.preventDefault();
      this.setState({ hasError: true, error: new Error(event.reason?.toString() || 'Promise rejection') });
    };

    window.addEventListener('error', handleUncaughtError);
    window.addEventListener('unhandledrejection', handlePromiseRejection);

    return () => {
      window.removeEventListener('error', handleUncaughtError);
      window.removeEventListener('unhandledrejection', handlePromiseRejection);
    };
  }

  handleRetry = () => {
    this.setState({ hasError: false, error: null });
    window.location.reload();
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen flex items-center justify-center bg-gray-50">
          <Result
            status="error"
            title="页面出错"
            subTitle="抱歉，页面出现了意外错误，请重试"
            extra={[
              <Button type="primary" key="retry" onClick={this.handleRetry}>
                重新加载
              </Button>,
            ]}
          />
        </div>
      );
    }

    return this.props.children;
  }
}

export { ErrorBoundary };