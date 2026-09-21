<div align="center">
  <img src="public/favicon.png" alt="Sublink Worker" width="120" height="120" />
  <h1>Sublink Worker</h1>
  <p>多平台代理订阅转换与管理工具。</p>

  <a href="https://github.com/eicky/sublink-worker/actions/workflows/test.yml"><img src="https://github.com/eicky/sublink-worker/actions/workflows/test.yml/badge.svg?branch=main" alt="Tests" /></a>
  <a href="https://github.com/eicky/sublink-worker/actions/workflows/docker-image.yml"><img src="https://github.com/eicky/sublink-worker/actions/workflows/docker-image.yml/badge.svg?branch=main" alt="Docker image" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT License" /></a>

  <p>
    <a href="https://deploy.workers.cloudflare.com/?url=https://github.com/eicky/sublink-worker"><img src="https://deploy.workers.cloudflare.com/button" alt="Deploy to Cloudflare Workers" /></a>
    <a href="https://vercel.com/new/clone?repository-url=https://github.com/eicky/sublink-worker&env=KV_REST_API_URL,KV_REST_API_TOKEN&envDescription=Redis%20REST%20credentials%20for%20persistent%20storage"><img src="https://vercel.com/button" alt="Deploy to Vercel" /></a>
  </p>
</div>

本仓库是后续开发、问题反馈和版本发布的维护入口，默认分支为 `main`。支持 Cloudflare Workers、Node.js、Vercel 和 Docker，同一份代码提供 Web 界面及订阅转换接口。

- [在线文档](https://eicky.github.io/sublink-worker/)
- [协议支持矩阵与验证说明](https://eicky.github.io/sublink-worker/protocol-support)
- [版本发布](https://github.com/eicky/sublink-worker/releases)
- [问题反馈](https://github.com/eicky/sublink-worker/issues)
- [参与开发](https://github.com/eicky/sublink-worker/pulls)

## 功能

- **协议输入**：AnyTLS、VLESS、VMess、Trojan、Shadowsocks、ShadowsocksR、Hysteria v1、Hysteria2 / HY2、TUIC。
- **订阅输入**：直接分享链接、Base64 / Base64URL、HTTP(S) 订阅，以及 Mihomo YAML、sing-box JSON、Surge INI。
- **客户端输出**：Mihomo / Clash.Meta、sing-box、Surge、Base64 分享链接订阅。
- **订阅管理**：多来源聚合、固定或随机短链、自定义规则、代理组和国家分组。
- **界面**：中文、英文、波斯语、俄语，支持浅色与深色主题。
- **存储**：Cloudflare KV、Redis、兼容的 Redis REST 服务，以及内存模式。

`hysteria://` 对应 v1；`hysteria2://` 和 `hy2://` 对应 v2。ShadowsocksR 独立解析，不会转换成 Shadowsocks。

目标客户端的能力仍然适用：例如当前 sing-box 不支持 SSR，Surge 不能表示部分协议和扩展。具体字段、传输方式和版本限制见[支持矩阵](docs/protocol-support.md)，不能无损转换的已识别组合会明确报错或标注 `Unsupported`。

## 快速开始

### 本地运行

开发环境使用 Node.js 22，具体版本见 [`.nvmrc`](.nvmrc)。

```sh
git clone https://github.com/eicky/sublink-worker.git
cd sublink-worker
npm ci
npm run dev:node
```

访问 `http://localhost:8787`。如需使用 Cloudflare Workers 本地运行时，将最后一条命令替换为 `npm run dev`。

### 独立程序包

从 [Releases](https://github.com/eicky/sublink-worker/releases) 下载 Windows、Linux 或 macOS 对应的压缩包，解压后在该目录运行：

```sh
# Linux / macOS
./sublink-worker

# Windows PowerShell
.\sublink-worker.exe
```

程序包已包含 `public/` Web 静态资源，默认监听 `8787` 端口。通过 `PORT` 及下方存储环境变量调整运行方式。Release 同时提供 `SHA256SUMS.txt`。

### Docker Compose

克隆本仓库后运行：

```sh
docker compose up -d
```

默认使用 `ghcr.io/eicky/sublink-worker:latest`，同时启动 Redis，并通过命名卷持久化数据。访问 `http://localhost:8787`。

更新镜像：

```sh
docker compose pull
docker compose up -d
```

可通过 `SUBLINK_WORKER_IMAGE` 指定其他镜像标签，配置见 [`docker-compose.yml`](docker-compose.yml)。

也可以仅运行转换器：

```sh
docker run -d --name sublink-worker -p 8787:8787 ghcr.io/eicky/sublink-worker:latest
```

独立运行时若未配置持久化存储，会使用内存模式；进程重启后短链和保存的配置会丢失。需要持久化时使用 Compose，或配置下面的 Redis 环境变量。

### Cloudflare Workers

使用顶部部署按钮，或在本地完成 `npm ci` 后运行：

```sh
npx wrangler login
npm run deploy
```

部署脚本会在当前 Cloudflare 账号下查找或创建 `SUBLINK_KV`，并更新 `wrangler.toml` 中的绑定。

### Vercel

使用顶部部署按钮导入本仓库，在项目设置中配置持久化存储。推荐配置 `KV_REST_API_URL` 与 `KV_REST_API_TOKEN`；也可使用 `REDIS_URL`。Vercel 入口和路由已包含在仓库中，无需另外编写接口。

## 环境变量

以下配置主要用于 Node.js / Docker / Vercel；Cloudflare Workers 使用平台的 KV binding。

| 变量 | 用途 |
|---|---|
| `PORT` | Node.js 监听端口，默认 `8787` |
| `REDIS_URL` | Redis 连接地址，支持 `redis://` 和 `rediss://` |
| `REDIS_HOST`、`REDIS_PORT` | 不使用连接地址时，单独指定 Redis 主机与端口 |
| `REDIS_USERNAME`、`REDIS_PASSWORD`、`REDIS_TLS` | Redis 认证及 TLS 配置 |
| `REDIS_KEY_PREFIX` | Redis 键前缀，用于隔离实例数据 |
| `KV_REST_API_URL`、`KV_REST_API_TOKEN` | 兼容的 Redis REST 存储服务 |
| `DISABLE_MEMORY_KV` | 设为 `true` 时禁用内存存储兜底 |
| `CONFIG_TTL_SECONDS` | 保存的配置有效期，默认 30 天；`0` 表示不过期 |
| `SHORT_LINK_TTL_SECONDS` | 短链有效期，单位为秒 |
| `STATIC_DIR` | 自定义静态资源目录 |

存储选择顺序为 Redis → Redis REST → 内存模式。

## 转换接口

| 路径 | 输出 |
|---|---|
| `/clash` | Mihomo / Clash.Meta YAML |
| `/singbox` | sing-box JSON，可通过 `singbox_version` 选择目标版本 |
| `/surge` | Surge INI |
| `/xray` | Base64 编码的原始分享链接列表，**不是 Xray JSON** |

通过 `config` 查询参数传入分享链接或订阅内容。参数应正确 URL 编码，例如：

```sh
curl --get 'http://localhost:8787/clash' \
  --data-urlencode 'config=trojan://example-password@node.example:443#Example'
```

示例仅用于说明接口格式，不是可连接的服务器。更多转换行为和限制见[协议文档](docs/protocol-support.md)。

## 开发与发布

```sh
npm test
npm run build:node
npm run build:native
npm run build
```

协议官方核心检查脚本及命令见[验证与复现](docs/protocol-support.md#验证与复现)。

- 代码、文档和后续修复在本仓库维护，问题请提交到本仓库的 Issues。
- `main` 推送会触发测试及 Docker 镜像构建；`v*.*.*` tag 会由 GitHub Actions 验证源码、构建 Windows/Linux/macOS 独立程序包、生成 SHA-256 校验文件并发布 Release。
- Docker 镜像发布到 `ghcr.io/eicky/sublink-worker`；主分支与版本 tag 都会更新 `latest`，版本 tag 同时保留同名镜像标签。
- Workers 自动部署使用 `CLOUDFLARE_API_TOKEN` 与 `CF_ACCOUNT_ID` 两个 GitHub Actions secrets；未配置时跳过部署。配置入口见 [Deploy Worker workflow](.github/workflows/deploy.yml)。
- 应用内版本检查使用本仓库的 GitHub Releases。发布版本时同步更新 `package.json`、`package-lock.json` 与 `src/constants.js` 中的版本号。

## 来源与许可

本项目基于 [7Sageer/sublink-worker](https://github.com/7Sageer/sublink-worker) 开发，感谢原作者及贡献者。

采用 [MIT License](LICENSE)，保留原项目版权与许可声明。
