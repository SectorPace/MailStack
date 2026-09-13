export class ApiError extends Error {
  public statusCode?: number;
  public details?: unknown;

  constructor(message: string, statusCode?: number, details?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.statusCode = statusCode;
    this.details = details;
  }
}

export function getErrorMessage(error: unknown, defaultMessage = 'An unexpected error occurred'): string {
  if (!error) return defaultMessage;
  let raw = '';
  if (typeof error === 'string') raw = error;
  else if (error instanceof Error) raw = error.message;
  else if (typeof error === 'object') {
    const obj = error as Record<string, unknown>;
    raw = (typeof obj.message === 'string' ? obj.message : '') || (typeof obj.error === 'string' ? obj.error : '');
    if (!raw) {
      try {
        raw = JSON.stringify(error);
      } catch {
        return defaultMessage;
      }
    }
  } else {
    raw = String(error);
  }

  if (
    raw.includes('PRIVILEGED_HELPER_UNAVAILABLE') ||
    raw.includes('helper failure') ||
    raw.includes('PRIVILEGED_OPERATION_FAILED')
  ) {
    return '特权助手未就绪：请确保已在 Linux 服务器上以 root 运行安装脚本并配置 mailstackctl.py 权限。';
  }
  if (raw.includes('PRIVILEGED_HELPER_TIMEOUT')) {
    return '特权操作超时：底层系统服务响应过慢，请稍后重试或检查系统负载。';
  }

  return raw || defaultMessage;
}
