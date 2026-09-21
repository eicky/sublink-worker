# 部署方式

所有运行方式使用同一套 Hono 应用。区别主要在持久化存储、静态资源和平台入口。

## 独立程序包

每个正式 Release 提供 Windows、Linux 与 macOS x64 程序包，内含可执行文件和 `public/` 静态资源。

1. 从 [GitHub Releases](https://github.com/eicky/sublink-worker/releases) 下载对应平台压缩包。
2. 使用 `SHA256SUMS.txt` 核验文件。
3. 解压后在该目录运行：

```sh
# Linux / macOS
./sublink-worker

# Windows PowerShell
.\sublink-worker.exe
```

默认监听 `8787`。例如改为 `9000`：

```sh
PORT=9000 ./sublink-worker
```

Windows PowerShell：

```powershell
$env:PORT = '9000'
.\sublink-worker.exe
```

未配置 Redis 或 Redis REST 时使用内存存储，重启后保存的配置和短链会丢失。

## Docker Compose

仓库内的 Compose 配置同时启动 Sublink Worker 与 Redis：

```sh
git clone https://github.com/eicky/sublink-worker.git
cd sublink-worker
docker compose up -d
```

默认镜像：

```text
ghcr.io/eicky/sublink-worker:latest
```

更新：

```sh
docker compose pull
docker compose up -d
```

如需固定版本：

```sh
SUBLINK_WORKER_IMAGE=ghcr.io/eicky/sublink-worker:v3.0.0 docker compose up -d
```

## Docker 单容器

```sh
docker run -d \
  --name sublink-worker \
  -p 8787:8787 \
  ghcr.io/eicky/sublink-worker:latest
```

单容器示例没有持久化存储。生产使用建议连接 Redis，或直接使用仓库的 Compose 配置。

## Cloudflare Workers

### 一键部署

[部署到 Cloudflare Workers](https://deploy.workers.cloudflare.com/?url=https://github.com/eicky/sublink-worker)

### 命令行部署

```sh
git clone https://github.com/eicky/sublink-worker.git
cd sublink-worker
npm ci
npx wrangler login
npm run deploy
```

`npm run deploy` 会检查或创建 `SUBLINK_KV` namespace，并更新 `wrangler.toml` 中的绑定后执行部署。GitHub Actions 自动部署需要设置：

- `CLOUDFLARE_API_TOKEN`
- `CF_ACCOUNT_ID`

没有配置这两个 secrets 时，工作流会明确跳过部署。

## Vercel

[导入到 Vercel](https://vercel.com/new/clone?repository-url=https://github.com/eicky/sublink-worker&env=KV_REST_API_URL,KV_REST_API_TOKEN)

Vercel 入口和 rewrite 已包含在仓库中。若需要持久化，请在项目设置中配置：

```text
KV_REST_API_URL
KV_REST_API_TOKEN
```

也可以配置 `REDIS_URL`。不配置持久化服务时会回退到实例内存，但 Serverless 实例之间和重启之后都不能保证数据存在。

## Node.js

```sh
npm ci
npm run build:node
node dist/node-server.cjs
```

静态资源默认从当前目录的 `public/` 读取；在其他工作目录启动时，通过 `STATIC_DIR` 指定绝对路径。

## GitHub Pages

GitHub Pages 只发布当前文档站，不运行转换接口。`.github/workflows/pages.yml` 在 `main` 的文档或站点配置变化后自动构建并部署到：

```text
https://eicky.github.io/sublink-worker/
```
