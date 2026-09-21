# 协议解析与客户端转换

本轮协议审查以 `3361ad72630bbd328a0a01c49f553aaa985889c3` 为基线，保留应用入口、订阅接口和三类 builder。当前实现与后续修复以本仓库的 `main` 分支为准；旧 fork 提交保留在 Git 历史中，旧解析补丁不再叠加到当前实现。

## 支持范围

`/clash` 的协议输出面向 **Mihomo / Clash.Meta**，不是已经停止维护的 classic Clash。`/xray` 输出 Base64 分享链接列表，不生成 Xray JSON，也不意味着 Xray 核心支持表中所有协议。

| 协议 | 分享链接输入 | Mihomo | sing-box | Surge |
|---|---|---|---|---|
| Shadowsocks | `ss://`；SIP002 明文、Base64URL userinfo，以及旧整串 Base64 格式 | 支持 | 支持；插件限目标内建插件 | 支持目标 cipher 与 simple-obfs |
| ShadowsocksR | `ssr://`；独立协议与嵌套 Base64URL 字段 | 支持 | 不支持，1.6 已移除 | 不支持 |
| VMess | v2rayN Base64(JSON)、Xray 分享链接 proposal 的 URI 形态 | 支持目标可表示的传输 | 支持目标可表示的传输 | TCP/WS；uTLS、旧 alter-ID 等不能无损转换时标注不支持 |
| VLESS | `vless://` | 支持，包括基础 XHTTP 和原生 `encryption` 字段 | 支持；不支持新版 VLESS encryption、XHTTP、TCP HTTP 伪装 | 不支持 |
| Trojan | `trojan://`；默认 TLS，密码解码一次 | TCP、WS/HTTPUpgrade、gRPC | TCP、WS、HTTP/H2、HTTPUpgrade、gRPC | TCP/WS |
| Hysteria v1 | `hysteria://`；query auth、带宽、peer、ALPN、xplus | 支持 | UDP；其他 v1 传输和 hopping 明确拒绝 | 不支持 |
| Hysteria v2 | `hysteria2://`、`hy2://` | 支持；含 hopping、Gecko、ECH | 支持；Gecko、随机 hopping 上界要求 1.14 目标 | 基础协议、下载带宽、hopping、Salamander/Gecko；不可表示选项标注不支持 |
| TUIC | `tuic://UUID:password@host:port`；本项目 v5 profile | 支持 v5；原生配置另可导入 v4 token | v5；v4 token、TUIC hopping 不支持 | 区分原生 `tuic` v4 和 `tuic-v5`；其他客户端的拥塞/0-RTT/heartbeat 等参数不能无损转换时标注不支持 |
| AnyTLS | `anytls://`；官方字段及已明确实现的客户端扩展 | 支持；不支持 AnyTLS + REALITY | 1.12 起支持；metadata 使用 1.14 目标 | 支持当前 AnyTLS v2；没有可等价映射的三个 idle-session 参数 |

这些是**协议与字段转换能力**，不是任意客户端版本、任意扩展组合都可用的保证。Surge 对不能转换的节点输出 `# ... Unsupported ...`，不把注释加入选择组；Mihomo/sing-box 对不可转换组合返回明确的配置错误。

### 不能混淆的语义

- `hysteria://` 是 v1，不再作为 v2 别名；`hy2` 才是 v2 别名。Realm 等其他 scheme 不在这次普通 Hysteria v1/v2 范围内。
- ShadowsocksR 不会退化成 Shadowsocks。
- TUIC 没有统一官方分享 URI；本项目采用 UUID/password 的 v5 profile，不猜测 token-only URI 的版本。
- HTTP/H2 传输与 TCP 的 HTTP header 伪装分别表示；不能都写成 `http` 后交给不同客户端猜测。
- WebSocket `path` 中的 Xray `ed` 是客户端早期数据参数，导出时从请求路径移除，映射到 `max_early_data` 和 `Sec-WebSocket-Protocol`。
- Xray gRPC 分享链接的 `mode=multi` 是客户端的 `TunMulti` 选择，不表示服务端只接受该方法。Mihomo/sing-box 使用同一 Xray 服务端同时提供的 `Tun` 方法，保留 service name、TLS/REALITY 等连接信息；不会写入不存在的 `grpc-mode` 字段。这是兼容转换，不是保留 multi 的分帧实现。若反向代理只放行 `TunMulti` 路径，则仍需调整该服务端路由。`guna` 和无法独立表示的自定义 authority 仍明确拒绝。
- TLS SNI、HTTP Host、uTLS client fingerprint、证书 fingerprint 是不同字段。Mihomo VLESS 使用 `servername`，不能发出会被忽略的 `sni` 字段。旧 VMess JSON 的隐式 SNI 按 v2rayN 规则从相应传输 Host 回退；新 authority-style URI 则按提案回退到服务器地址。
- 整证书 SHA-256 pin 不能替换成公钥 SHA-256 pin：保留原校验策略时，VLESS/VMess 的单个 `pcs` 指纹映射到 Mihomo `fingerprint`，不会误当作 `client-fingerprint`；Mihomo/Surge 可表示整证书 pin，sing-box 不能表示时明确拒绝。空 `pcs` 表示未设置，非法或当前不能表示的多指纹列表明确拒绝。页面和 `/clash`、`/singbox` 默认采用下述跳过校验策略，移除约束而不是伪装成另一种指纹。
- Hysteria2 官方 ECH 的 Base64 在内部规范化为 `ECH CONFIGS` PEM；Mihomo 输出转回 Base64，sing-box 输出保留 PEM。
- TUIC 的 `disable_sni` 不是跳过证书验证。Mihomo 会把二者耦合，未显式允许 insecure 时不能这样转换。
- sing-box `network` 是 TCP/UDP 限制，不是 WS/gRPC 等传输类型。未指定时不再错误地禁用 UDP；显式 TCP-only 保留。
- 未启用 TLS 时，sing-box 输出省略整个 `tls` 块，而不是写入 `{ enabled: false }`。sing-box 1.14.1 的部分原生出站按块是否存在选择 TLS dialer，禁用块也可能触发运行时空指针崩溃；`sing-box check` 检查不出这个问题。
- AnyTLS session 时间在 Mihomo 是整数秒，在 sing-box 是 Duration；TUIC heartbeat 在 Mihomo 是毫秒，在 sing-box 是 Duration。

### 代理服务器证书校验策略

为优先兼容性，页面和 `/clash`、`/singbox` **默认开启**「跳过代理服务器证书校验」。未带参数的旧转换链接也使用该默认值。需要保留原订阅的校验策略时，在「高级选项 → 通用设置」关闭此项，或添加 `skip_cert_verify=false`：

- 对普通 TLS 代理设置 Mihomo `skip-cert-verify: true` / sing-box `tls.insecure: true`，同时移除整证书 pin、公钥 pin 和自定义服务端 CA 约束。包括 VLESS `pcs`、Hysteria2 `pinSHA256` 导入的约束。
- TLS 加密、SNI、ALPN、uTLS 客户端指纹、客户端证书保持不变；**不再验证代理服务器身份**。明文节点不会被改成 TLS，REALITY 参数和验证方式也不改变。
- 同格式远程订阅会展开成内联节点，让转换时的选项实际生效；节点更新需刷新转换订阅。已存储基础配置中的代理节点也会处理。若配置自行声明了远程 providers，返回明确错误，需先展开节点，避免只对一部分节点生效。
- 选项随生成链接、短链、链接恢复与本地表单偏好保存。新链接明确写入 `true` 或 `false`，已保存的关闭选择会保留。`false` 保留原订阅策略，并非强制覆盖原订阅的 insecure 设置。
- 作用范围是代理节点的原生 TLS 配置，不修改 Shadowsocks 插件、订阅下载、规则下载或 DNS 的 TLS 校验；Surge 和 `/xray` Base64 输出不受此开关影响。

Xray 26.3.27 的 `allowInsecure=true` 已在其日期门槛后被拒绝。删除此字段会恢复证书验证，**不等于跳过验证**；原来的 `pcs`、SNI 等仍需保留。`/xray` 仍输出原分享链接，不生成或自动改写 Xray 原生 JSON。

## 输入与错误处理

支持直接 URI、Base64/Base64URL 订阅、远程 HTTP(S) 订阅、Mihomo YAML、sing-box JSON、Surge INI。

- 只解码订阅外层 envelope，不对已经是 URI/YAML/JSON 的正文再整体 percent-decode，避免破坏密码中的 `%3F`、`%23`、`%25`。
- 缺备注节点会获得可选择的默认名称；IPv6 地址在内部不带方括号，端口独立存储。
- 端口、重复 query、凭据编码、协议枚举和相关参数错误会被报告，不再吞掉已识别协议的错误并输出空配置。
- 仅同格式输入合并其非代理配置；跨格式保留代理与已规范化的代理组，不把 sing-box `route`/`dns` 原样塞进 Mihomo，也不把 Mihomo listener/DNS 字段塞进 sing-box。
- Surge 字符串使用 quote-aware 分词，保留带逗号的密码与多 ALPN；未文档化的嵌套引号/转义形式明确拒绝，不发明新的客户端语法。

## 验证与复现

自动回归覆盖协议 parser、输入格式转换、builder、远程订阅和公共 HTTP 转换入口：

```sh
npm test
npm run build:node
npm run build
```

官方核心配置检查：

```sh
node scripts/check-protocol-configs.mjs --sing-box /path/to/sing-box --mihomo /path/to/mihomo
# 单独复查一个案例：
node scripts/check-protocol-configs.mjs --sing-box /path/to/sing-box --mihomo /path/to/mihomo --only hy2-ech
```

本轮固定的核心版本为 **sing-box 1.14.1** 与 **Mihomo 1.19.31**。脚本使用虚构凭据，从真实 URI parser 经真实 builder 生成最小配置，调用官方 `sing-box check` / `mihomo -t`，并清理临时配置。目标不支持的组合单独断言明确拒绝。

2026-09-20 初轮协议审查验收：

- Vitest：**44 个文件、492 项测试通过**。
- 官方核心脚本：**50 项检查通过**，其中 47 项为真实核心加载检查，3 项为明确拒绝不支持组合的边界检查。
- `npm run build:node`、`npm run build`：通过。
- `git diff --check`：通过。

### gRPC 与证书校验互通

Mihomo 会忽略部分未知字段，所以配置加载通过不等于连接可用。除固定版本源码与字段断言外，还提供官方核心间的实际通信检查（需要 OpenSSL）：

```sh
node scripts/check-client-interop.mjs \
  --xray /path/to/xray \
  --mihomo /path/to/mihomo \
  --sing-box /path/to/sing-box
```

脚本只使用本机回环地址、虚构账号和临时证书，不访问真实代理服务器；结束后关闭核心进程并清理临时文件。Xray **26.3.27** 服务端搭配上述两个客户端版本已验证：

- 明文 VLESS/TCP 在两个客户端均可完成 HTTP 请求，不会因多余的禁用 TLS 块触发崩溃。
- VLESS / VMess / Trojan 的 `mode=multi` 分享链接转换后，可以通过 gRPC 完成 HTTP 请求。
- Xray 服务端 `multiMode` 开启或关闭时，VLESS 客户端兼容方式均可连接。
- VLESS gRPC + REALITY 能完成实际握手和 HTTP 请求。
- 保留原校验策略时：Mihomo 使用正确 `pcs` 时通过、错误指纹时拒绝；sing-box 不能表示整证书 pin 时明确拒绝，普通 TLS 互通只信任测试临时 CA。
- 未跳过校验时两个客户端均拒绝未受信的自签名证书；开启 `skip_cert_verify` 后，可在没有安装该 CA、分享链接携带错误 pin 的情况下完成 HTTP 请求。
- 开启选项不影响明文 VLESS 或 REALITY 的互通；脚本共覆盖 24 项真实连接或明确拒绝检查。

这些检查不等于所有公网节点在所有网络环境下都可用。Surge 没有本机可用的官方 Windows 校验器，其转换依据当前官方手册和回归测试，不宣称已在 Surge App 中验证。

## 一手资料

- [经典协议来源与格式区分](https://github.com/eicky/sublink-worker/blob/main/docs/research/2026-09-20-protocol-classic-sources.md)
- [Hysteria、TUIC、AnyTLS 官方资料与客户端差异](https://github.com/eicky/sublink-worker/blob/main/docs/research/2026-09-20-protocol-modern-sources.md)
- [SSR 原始项目协议资料](https://github.com/eicky/sublink-worker/blob/main/docs/research/2026-09-20-protocol-ssr-sources.md)
- [固定版本客户端字段合同](https://github.com/eicky/sublink-worker/blob/main/docs/research/2026-09-20-client-protocol-contracts.md)
- [Xray WebSocket early data 实现](https://github.com/XTLS/Xray-core/blob/dcdfc57ccdad496e192344788a7d14a8d4c88573/infra/conf/transport_method.go)
- [Mihomo VLESS 字段定义](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/adapter/outbound/vless.go)
- [Xray gRPC 官方实现](https://github.com/XTLS/Xray-core/tree/v26.3.27/transport/internet/grpc)
- [Mihomo Tun 客户端实现](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/transport/gun/gun.go)
- [Xray 分享链接 proposal：pcs](https://github.com/XTLS/Xray-core/discussions/716)
- [Mihomo 证书 SHA-256 校验实现](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/component/ca/fingerprint.go)
- [Surge 当前 TLS 参数](https://manual.nssurge.com/policies/tls.html)
