# 项目概览

Sublink Worker 是一个自托管的代理订阅转换与管理工具。它把不同来源的节点解析为统一的内部结构，再由目标客户端适配器生成配置，避免把相似但不等价的字段直接复制到另一种格式。

## 能处理什么

### 输入

- `ss://`、`ssr://`、`vmess://`、`vless://`、`trojan://`
- `hysteria://`、`hysteria2://`、`hy2://`、`tuic://`、`anytls://`
- Base64 / Base64URL 订阅
- HTTP(S) 远程订阅
- Mihomo YAML、sing-box JSON、Surge INI

### 输出

| 路径 | 输出格式 |
|---|---|
| `/clash` | Mihomo / Clash.Meta YAML |
| `/singbox` | sing-box JSON |
| `/surge` | Surge INI |
| `/xray` | Base64 编码的分享链接列表，不是 Xray JSON |

不同目标客户端的能力并不相同。解析成功不代表每个输出端都能表达该节点；具体差异见[协议支持矩阵](/protocol-support)。

## 本地运行

开发环境使用仓库 [`.nvmrc`](https://github.com/eicky/sublink-worker/blob/main/.nvmrc) 指定的 Node.js 版本。

```sh
git clone https://github.com/eicky/sublink-worker.git
cd sublink-worker
npm ci
npm run dev:node
```

默认访问：

```text
http://localhost:8787
```

Cloudflare Workers 本地运行：

```sh
npm run dev
```

## 第一次转换

下面的地址和凭据是虚构示例：

```sh
curl --get 'http://localhost:8787/clash' \
  --data-urlencode 'config=trojan://example-password@node.example:443#Example'
```

返回值是 Mihomo YAML。将路径换成 `/singbox` 或 `/surge` 即可请求其他目标格式。

## 选择部署方式

| 场景 | 推荐方式 |
|---|---|
| 无服务器、低运维 | Cloudflare Workers |
| 已使用 Vercel | Vercel |
| 服务器上已有 Redis | Docker Compose |
| 本机或轻量服务器 | GitHub Release 独立程序包 |
| 二次开发 | Node.js 源码运行 |

继续阅读[部署方式](/guide/deployment)。

## 数据流与隐私

GitHub Pages 文档站是静态站点，不处理任何订阅。订阅内容只会提交到你访问的转换服务实例。远程订阅转换时，服务实例需要代表你访问订阅地址，因此不要使用不受信任的公开实例处理敏感订阅。
