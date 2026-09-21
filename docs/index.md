---
layout: home

hero:
  name: Sublink Worker
  text: 一份订阅，多端可用
  tagline: 将分享链接与不同客户端配置规范化为 Mihomo、sing-box、Surge 或 Base64 URI 订阅，支持 Workers、Vercel、Node.js、Docker 与独立程序包。
  image:
    src: /logo.svg
    alt: Sublink Worker
  actions:
    - theme: brand
      text: 快速开始
      link: /guide/getting-started
    - theme: alt
      text: 部署服务
      link: /guide/deployment
    - theme: alt
      text: 查看协议支持
      link: /protocol-support

features:
  - icon: ⇄
    title: 统一转换入口
    details: 解析直接分享链接、远程订阅、Mihomo YAML、sing-box JSON 与 Surge INI，再按目标客户端能力输出。
  - icon: ◈
    title: 明确的兼容边界
    details: Hysteria v1/v2、SSR、TLS、传输层与客户端扩展分别处理；不能无损表达时明确报错或标注 Unsupported。
  - icon: ⎈
    title: 多运行时部署
    details: 同一套 Hono 应用运行在 Cloudflare Workers、Vercel、Node.js、Docker 和 GitHub Release 独立程序包。
  - icon: ◇
    title: 可选持久化
    details: 支持 Cloudflare KV、Redis、Redis REST 与内存模式，用于保存基础配置和短链。
  - icon: ◎
    title: 自动化验证
    details: Vitest 覆盖 parser、builder、订阅与 HTTP 入口，并可调用固定版本的 sing-box 和 Mihomo 核验生成配置。
  - icon: ⚙
    title: 自托管优先
    details: 文档站不接收订阅内容；转换请求只发送到你自行部署的服务实例。
---

## 文档站与转换服务的关系

本站通过 GitHub Pages 提供静态文档，不执行订阅转换，也不保存配置。实际服务需要部署到 Cloudflare Workers、Vercel、Node.js 或 Docker：

```text
GitHub Pages                 文档、部署说明、协议矩阵
Cloudflare / Vercel / Node   Web 界面、转换接口、短链
GitHub Container Registry    amd64 / arm64 Docker 镜像
GitHub Releases              Windows / Linux / macOS 独立程序包
```

::: tip 从哪里开始
首次使用建议先阅读[项目概览](/guide/getting-started)，然后根据运行环境选择[部署方式](/guide/deployment)。转换异常时，先检查[协议支持矩阵](/protocol-support)中的目标客户端限制。
:::
