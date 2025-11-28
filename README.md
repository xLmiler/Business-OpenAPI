# Business Gemini Pool

一个轻量级、高性能的 Gemini Business 账号代理池，提供完全兼容 OpenAI 格式的 API 接口。

## 功能特性

- **智能账号池管理**：支持自动 Token 刷新、健康检查以及智能冷却处理，确保服务高可用。
- **兼容 OpenAI**：完全兼容标准的 OpenAI 库和客户端，可直接替代现有工作流。
- **现代化控制台**：提供美观、响应式的 Web 界面，用于实时监控账号状态和管理配置。
- **Docker 支持**：开箱即用的 Docker 镜像，轻松部署和扩展。

## 快速开始

### Docker 部署（推荐）

```bash
# 构建镜像
docker build -t gemini-pool .

# 启动容器
docker run -d \
  -p 7860:7860 \
  -e ADMIN_KEY=your_secret_password \
  --name gemini-pool \
  gemini-pool
```

### 本地开发

1. **安装依赖**
   ```bash
   pip install -r requirements.txt
   ```

2. **启动服务**
   ```bash
   # 默认端口为 3000
   python gemini.py
   ```

## 配置说明

关键环境变量配置如下：

| 变量名 | 描述 | 默认值 |
|--------|------|--------|
| `PORT` | 服务监听端口 | `3000` (本地) / `7860` (Docker) |
| `ADMIN_KEY` | Web 控制台管理员密码 | `admin123` |
| `REGISTER_SERVICE_URL` | 注册服务 URL 前缀 | `http://localhost:5000` |
| `REGISTER_ADMIN_KEY` | 注册服务管理员密钥 | `sk-admin-token` |
| `ACCOUNT_LIFETIME` | 账号生命周期 (秒) | `43200` (12小时) |
| `REFRESH_BEFORE_EXPIRY` | 提前刷新时间 (秒) | `3600` (1小时) |
| `REFRESH_BATCH_SIZE` | 刷新队列批量大小 | `1` |
| `MAX_RETRIES` | 最大重试次数 | `10` |
| `LOG_LEVEL` | 日志级别 | `INFO` |

## 使用指南

### Web 控制台
访问 `http://localhost:7860` (或您配置的端口) 进入控制台，进行账号的添加和管理。

### API 集成
将您的 OpenAI 客户端指向本地服务地址：

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:7860/v1",
    api_key="any"  # API Key 默认不进行验证
)

response = client.chat.completions.create(
    model="gemini-2.5-pro",
    messages=[{"role": "user", "content": "你好，世界！"}]
)
print(response.choices[0].message.content)
```

## 许可证

本项目仅供学习交流使用。
