# 常见问题

## GitHub Pages 能直接做订阅转换吗？

不能。GitHub Pages 只托管静态文档，不执行 Hono、Node.js、KV 或远程订阅请求。请把转换服务部署到 Workers、Vercel、Node.js 或 Docker，然后把该服务地址添加到客户端。

## `/xray` 为什么不是 Xray JSON？

该路径返回 Base64 编码的分享链接列表，用于兼容常见订阅消费方式。它不构建 Xray JSON，也不代表 Xray 核心支持项目中的全部输入协议。

## 为什么同一个节点不能输出到所有客户端？

客户端能力不同。例如当前 sing-box 已移除 ShadowsocksR，Surge 不支持 VLESS，部分 TLS、transport、端口跳跃和插件字段也没有同构表达。项目会明确拒绝有损转换，而不是伪装成另一种协议。

## `hysteria://` 和 `hy2://` 有什么区别？

- `hysteria://`：Hysteria v1
- `hysteria2://`、`hy2://`：Hysteria v2

两代协议字段不同，不应互相当作别名。完整差异见[协议支持矩阵](/protocol-support)。

## 为什么 SSR 到 sing-box 返回错误？

sing-box 从 1.6 起移除了 ShadowsocksR。SSR 可以输出到 Mihomo，但不会降级成 Shadowsocks。

## 独立程序包启动后页面是空白或 404

压缩包中的可执行文件必须与 `public/` 目录保持相对位置，并从解压后的目录启动。自定义目录时设置：

```text
STATIC_DIR=/absolute/path/to/public
```

## 重启后短链消失了

当前实例正在使用内存模式。配置 Redis、Redis REST 或 Cloudflare KV 后再创建需要长期保存的短链。

## Docker 镜像有哪些标签？

- `latest`：最近一次 `main` 或版本 tag 构建
- `v3.0.0`：对应正式版本
- `sha-...`：对应提交的追踪标签

生产部署建议固定版本标签，并在验证后主动升级。

## 如何更新？

- Docker Compose：`docker compose pull && docker compose up -d`
- 独立程序包：从 [Releases](https://github.com/eicky/sublink-worker/releases) 下载新版本并替换整个解压目录
- Workers / Vercel：同步仓库 `main` 后重新部署
- 源码运行：拉取代码后执行 `npm ci` 与相应构建命令

## 如何报告问题？

提交到 [GitHub Issues](https://github.com/eicky/sublink-worker/issues)，请提供：

- 输入格式类型与目标客户端，不要附真实密码或订阅 token
- 目标客户端及版本
- 可使用虚构数据复现的最小链接或配置
- 返回的错误信息

协议兼容问题最好同时指出对应协议或客户端的官方文档。
