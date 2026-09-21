# 环境配置

## 存储选择顺序

Node.js、Docker 和 Vercel 按以下顺序选择 KV adapter：

1. Redis：`REDIS_URL`，或 `REDIS_HOST` + `REDIS_PORT`
2. Redis REST：`KV_REST_API_URL` + `KV_REST_API_TOKEN`
3. 内存模式

如果设置 `DISABLE_MEMORY_KV=true` 且没有可用的外部存储，需要持久化能力的接口会返回依赖缺失错误，而不是静默保存到内存。

Cloudflare Workers 使用 `SUBLINK_KV` binding。

## 环境变量

| 变量 | 适用环境 | 说明 |
|---|---|---|
| `PORT` | Node / Docker / 独立程序 | HTTP 监听端口，默认 `8787` |
| `STATIC_DIR` | Node / 独立程序 | Web 静态资源目录，默认 `public` |
| `REDIS_URL` | Node / Docker / Vercel | 完整 Redis 连接地址，支持 `redis://` 与 `rediss://` |
| `REDIS_HOST` | Node / Docker | Redis 主机；需与 `REDIS_PORT` 同时设置 |
| `REDIS_PORT` | Node / Docker | Redis 端口 |
| `REDIS_USERNAME` | Node / Docker | Redis 用户名，可选 |
| `REDIS_PASSWORD` | Node / Docker | Redis 密码，可选 |
| `REDIS_TLS` | Node / Docker | 设为 `true` 启用 TLS options |
| `REDIS_KEY_PREFIX` | Node / Docker / Vercel | Redis 键前缀，用于隔离同一实例上的数据 |
| `KV_REST_API_URL` | Node / Vercel | Redis REST 服务地址 |
| `KV_REST_API_TOKEN` | Node / Vercel | Redis REST token |
| `DISABLE_MEMORY_KV` | Node / Vercel | 设为 `true` 禁止内存存储兜底 |
| `CONFIG_TTL_SECONDS` | 所有运行时 | 保存配置的有效期；默认 30 天，`0` 表示不过期 |
| `SHORT_LINK_TTL_SECONDS` | 所有运行时 | 短链有效期；未设置时由运行时配置决定 |

## Docker Compose 示例

仓库默认 Compose 已配置 Redis：

```yaml
services:
  worker:
    image: ghcr.io/eicky/sublink-worker:latest
    environment:
      REDIS_HOST: redis
      REDIS_PORT: 6379
      REDIS_KEY_PREFIX: sublink
      CONFIG_TTL_SECONDS: 2592000
```

敏感值建议通过 `.env`、Docker secrets 或部署平台的 secrets 管理，不要写入公开仓库。

## TTL 注意事项

- `CONFIG_TTL_SECONDS=0`：保存的基础配置不过期。
- 正整数：按秒设置过期时间。
- 内存模式下 TTL 只在当前进程生命周期内有意义。
- 短链和基础配置使用不同的 key 与 TTL。

## Cloudflare KV

`wrangler.toml` 中必须存在：

```toml
kv_namespaces = [
  { binding = "SUBLINK_KV", id = "<YOUR_NAMESPACE_ID>" }
]
```

不要复制其他账号的 namespace ID。执行 `npm run deploy` 时，仓库脚本会在当前账号中寻找或创建对应 namespace。
