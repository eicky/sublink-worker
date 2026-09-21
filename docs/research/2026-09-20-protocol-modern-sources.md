# Hysteria 1/2、TUIC、AnyTLS 与客户端字段的官方来源

- 调研日期：2026-09-20
- 用途：为 URI parser、内部协议对象以及 sing-box / Mihomo builder 提供可核验 contract
- 来源原则：只采用协议作者、官方项目、官方客户端源码、官方文档和协议依赖的标准库源码；第三方 `tuic://` 约定不作为 TUIC 官方规范

## 结论

1. Hysteria 2 的官方普通分享 scheme 是 `hysteria2://`，官方 parser 另接受 `hy2://`；`hysteria://` 属于 Hysteria 1。官方明确说明 Hysteria 2 与 1.x 不兼容，不能把 `hysteria://` 静默当成 v2。
2. TUIC 没有官方分享 URI 标准。当前官方仓库只维护 wire spec，且维护者明确把分享链接格式交由社区演化。因此 UUID/password 的 URI userinfo 布局、percent-encoding、IPv6 authority、query key 和布尔文本都没有 TUIC 官方答案。
3. AnyTLS 有官方 `anytls://` 约定：密码位于 URI username，特殊字符按 RFC 3986 percent-encode，IPv6 使用方括号，端口缺失时为 443，标准 query 只有 `sni`、`insecure`。但 `anytls-go` 样例客户端的 parser 并未完整实现这份文档，不能反过来覆盖规范。
4. Hysteria 2 官方 URI 不定义用户可配 `alpn`，AnyTLS 官方 URI 也不定义 `alpn`；sing-box / Mihomo 的 TLS 字段是客户端配置能力，不等于上游分享链接字段。
5. Hysteria 2 port hopping 的官方 URI/address 语法使用 `host:port,port-range`；sing-box `server_ports` 使用 `start:end` 列表，Mihomo `ports` 使用 `start-end` 且以 `/` 或 `,` 分隔，三者不能原样复制。
6. TUIC v5 的官方 wire 行为与已移除的历史 reference client 配置要分层描述。`congestion_control`、`zero_rtt_handshake`、具体 heartbeat 默认值属于客户端配置，不是 wire spec 字段。
7. AnyTLS 没有 `maxIdleSession`。官方协议参数和官方 Go client API只有检查间隔、空闲超时、最低保留数；sing-box 和 Mihomo 也都没有对应最大值字段。

## 固定的来源快照

| 项目 | 本文采用的官方快照 |
|---|---|
| Hysteria 2 | [`HyNetworks/hysteria@e1366b1`](https://github.com/HyNetworks/hysteria/tree/e1366b173ccf5706e1e4630fe8aa654a4b574085)，官方文档 [`hysteria-website@d5c6fa4`](https://github.com/HyNetworks/hysteria-website/tree/d5c6fa441ab31b7726205ae4451f828cebe5263d)；均对应 v2.12.3 时代 |
| Hysteria 1 | [`HyNetworks/hysteria@57c5164`](https://github.com/HyNetworks/hysteria/tree/57c5164854d6cfe00bead730cce731da2babe406)（v1.3.5）及官方归档站 [`v1.hysteria.network`](https://v1.hysteria.network/) |
| TUIC | 当前协议仓库 [`tuic-protocol/tuic@8e118f2`](https://github.com/tuic-protocol/tuic/tree/8e118f242f24a17a9f487dc344cc50d7e63e557e)；历史官方 v5 reference client [`@a299ef0`](https://github.com/tuic-protocol/tuic/tree/a299ef02d9f4ab5a0edbf58b9998f41bf768b332)；历史 v4/client 0.8.5 [`@0303155`](https://github.com/tuic-protocol/tuic/tree/0303155b28a24cd0fa2e9efa8832dd914fe74a5a) |
| AnyTLS | 参考实现 [`anytls/anytls-go@fd6167a`](https://github.com/anytls/anytls-go/tree/fd6167acd6d73b9fa3e607659951847fbc9e6c50)，官方库 [`anytls/sing-anytls@479cb5b`](https://github.com/anytls/sing-anytls/tree/479cb5bd490a2f4b1b6e8cd82b821afb392a94c8) |
| sing-box | v1.14.1 commit [`1ac1a33`](https://github.com/SagerNet/sing-box/tree/1ac1a339cb1223e9c70eae14c44411c75033c02d)，锁定的 [`SagerNet/sing-quic@4ab2ece`](https://github.com/SagerNet/sing-quic/tree/4ab2eceaac81e073f53b22ec72ff56aaea89a3d1) |
| Mihomo | v1.19.31 commit [`ab405ba`](https://github.com/MetaCubeX/mihomo/tree/ab405bad5beeeac8b003bb01f60f134f6df54471)，官方文档 [`Meta-Docs@517f4c2`](https://github.com/MetaCubeX/Meta-Docs/tree/517f4c2303aae17eee681129bde6422e9f7a4e67) |

版本固定很重要：Hysteria 2 的 Gecko、sing-box 的 `server_ports` / `hop_interval_max`、Mihomo 的随机 hop interval 和 AnyTLS 都是后期加入的能力。

## 一、Hysteria 2

### 1. Scheme、版本与 `hysteria://`

Hysteria 2 官方普通 URI：

```text
hysteria2://[auth@]hostname[:port]/?[key=value]&[key=value]...[#name]
```

官方文档定义 `hysteria2`，官方原生 parser 接受 `hysteria2` 和 `hy2`，官方 `share` 命令固定生成 `hysteria2://`：

- [`hysteria-website/docs/docs/developers/URI-Scheme.md`](https://github.com/HyNetworks/hysteria-website/blob/d5c6fa441ab31b7726205ae4451f828cebe5263d/docs/docs/developers/URI-Scheme.md#L7-L50)
- [`hysteria/app/cmd/client.go::clientConfig.URI, parseURI`](https://github.com/HyNetworks/hysteria/blob/e1366b173ccf5706e1e4630fe8aa654a4b574085/app/cmd/client.go#L518-L620)
- [`hysteria/app/cmd/share.go`](https://github.com/HyNetworks/hysteria/blob/e1366b173ccf5706e1e4630fe8aa654a4b574085/app/cmd/share.go#L17-L22)

Hysteria 1 官方 URI 则是：

```text
hysteria://host:port?protocol=...&auth=...&peer=...&insecure=1&upmbps=...&downmbps=...&alpn=...&obfs=...&obfsParam=...#remarks
```

来源：[`Hysteria 1 URI Scheme`](https://v1.hysteria.network/docs/uri-scheme/)。官方迁移页明确写明 “Hysteria 2 is NOT compatible with Hysteria 1.x”：[`2-vs-1.md`](https://github.com/HyNetworks/hysteria-website/blob/d5c6fa441ab31b7726205ae4451f828cebe5263d/docs/docs/misc/2-vs-1.md#L1-L20)。

Hysteria 1 URI 参数 contract：

| 字段 | 官方 v1 语义 |
|---|---|
| host / port | 都必须显式给出；v1 URI 文档没有默认端口，也未单独规定 IPv6 authority 写法 |
| `protocol` | 可选，`udp` / `wechat-video` / `faketcp`，默认 `udp`；v1.3.5 源码还接受 `wechat` alias |
| `auth` | 可选的普通认证字符串；不是 v2 userinfo，也不是 sing-box 的 Base64 `auth` |
| `peer` | TLS SNI / certificate name |
| `insecure` | 跳过证书错误；官方示例使用 `1`，文档未穷举 bool 文本 |
| `upmbps` / `downmbps` | 必填，单位 Mbps |
| `alpn` | 可选的 QUIC ALPN；v1.3.5 原生默认 `hysteria` |
| `obfs` / `obfsParam` | mode 为空或 `xplus`；`obfsParam` 是 obfs password |

协议 transport、默认 ALPN 与 TLS 映射还可由 v1.3.5 [`app/cmd/client.go`](https://github.com/HyNetworks/hysteria/blob/57c5164854d6cfe00bead730cce731da2babe406/app/cmd/client.go) 和 [`app/cmd/config.go`](https://github.com/HyNetworks/hysteria/blob/57c5164854d6cfe00bead730cce731da2babe406/app/cmd/config.go) 核验。v1 URI 页面没有定义 percent-encoding、重复 query、默认端口或带宽小数规则；本项目为跨目标无损转换收紧为标准 URI 解码、显式端口和正整数 Mbps。

因此：

- `hysteria2://`、`hy2://` → Hysteria 2；
- `hysteria://` → Hysteria 1；
- 把 `hysteria://` 当 v2 只能是某个第三方实现的私有兼容，不能标为官方别名。

### 2. Auth、密码与 URL 编码

`auth` 位于 URI userinfo。官方要求包含特殊字符时 percent-encode；若服务器使用 `userpass` authenticator，规范表示是 `username:password`：

```text
hysteria2://alice:p%40ss%3Aword@example.com:443/
```

这里第一个未编码的 `:` 是 user/password 语法分隔符；数据中的 `@`、`:`、`/`、`?`、`#`、`%` 应编码。官方生成器和 parser 的行为是：

1. `clientConfig.URI()` 按第一个 `:` 拆运行时 `Auth`；
2. 使用 `url.UserPassword` 或 `url.User` 分别编码 userinfo；
3. `parseURI()` 通过 `Username()` / `Password()` percent-decode；
4. 有 password 部分时重新组合为 `username + ":" + password`。

来源：

- [`app/cmd/client.go#L518-L620`](https://github.com/HyNetworks/hysteria/blob/e1366b173ccf5706e1e4630fe8aa654a4b574085/app/cmd/client.go#L518-L620)
- [`app/internal/url/url.go::Userinfo.String`](https://github.com/HyNetworks/hysteria/blob/e1366b173ccf5706e1e4630fe8aa654a4b574085/app/internal/url/url.go#L424-L434)
- [`app/internal/url/url.go::parseAuthority`](https://github.com/HyNetworks/hysteria/blob/e1366b173ccf5706e1e4630fe8aa654a4b574085/app/internal/url/url.go#L583-L615)

malformed `%` escape 会导致 URI 解析失败。实现可以接受把整个 `alice:secret` 编成一个 username 的非 canonical 写法，但生成器应遵循官方 `userpass` 表示，不以宽松输入行为定义输出格式。

### 3. IPv6

官方普通配置使用 bracketed IPv6 authority，例如：

```yaml
server: "[2001:db8::1]:443"
```

来源：[`getting-started/Client.md`](https://github.com/HyNetworks/hysteria-website/blob/d5c6fa441ab31b7726205ae4451f828cebe5263d/docs/docs/getting-started/Client.md#L13-L20)。官方自定义 URL parser 也专门解析 `[IPv6]`、`[IPv6]:port` 以及 `[IPv6]:port,range`：

- [`app/internal/url/url.go::parseHost`](https://github.com/HyNetworks/hysteria/blob/e1366b173ccf5706e1e4630fe8aa654a4b574085/app/internal/url/url.go#L618-L666)
- [`app/internal/url/url.go::validOptionalPort`](https://github.com/HyNetworks/hysteria/blob/e1366b173ccf5706e1e4630fe8aa654a4b574085/app/internal/url/url.go#L774-L789)

可移植形式：

```text
hysteria2://auth@[2001:db8::1]:443/
hysteria2://auth@[2001:db8::1]:443,5000-6000/
```

不要用未加方括号的 IPv6 authority。URI 文档一般规则是省略端口默认 443；但当前 v2.12.3 的 `parseServerAddrString` fallback 会把原始 host 再交给 `net.JoinHostPort`，对已经带括号且无端口的 IPv6 存在形成双括号的实现风险：[`app/cmd/client.go#L1238-L1252`](https://github.com/HyNetworks/hysteria/blob/e1366b173ccf5706e1e4630fe8aa654a4b574085/app/cmd/client.go#L1238-L1252)。生成 IPv6 链接时显式保留 `:443` 最稳妥；这是当前实现 caveat，不改变文档层的默认端口语义。

### 4. Port hopping

Hysteria 2 官方地址语法：

```text
host:port[,port-or-range...]
```

示例：

```text
example.com:1234,5678,9012
example.com:20000-50000
example.com:1234,5000-6000,7044,8000-9000
```

可组合任意数量的独立端口和范围。客户端随机选择初始端口，随后周期性切换。固定 interval 为 `transport.udp.hopInterval`，默认 `30s`、最小 `5s`；也可以改用 `minHopInterval` / `maxHopInterval` 选择随机 interval，两种形式互斥：[`Port-Hopping.md`](https://github.com/HyNetworks/hysteria-website/blob/d5c6fa441ab31b7726205ae4451f828cebe5263d/docs/docs/advanced/Port-Hopping.md#L7-L51)。

源码的 `PortUnion` 进一步表明范围端点包含在内，并会排序、合并相邻/重叠范围、去重；非法空段、非十进制、多个 `-`、超出 `uint16` 会失败：

- [`extras/utils/portunion.go`](https://github.com/HyNetworks/hysteria/blob/e1366b173ccf5706e1e4630fe8aa654a4b574085/extras/utils/portunion.go#L9-L97)
- [`extras/utils/portunion_test.go`](https://github.com/HyNetworks/hysteria/blob/e1366b173ccf5706e1e4630fe8aa654a4b574085/extras/utils/portunion_test.go#L9-L150)

内部 utility 还认识 `all` / `*`，但 URI host parser 只允许数字、`,`、`-`，官方 URI 文档也未列出它们，故不得生成 `host:all` 或 `host:*`。可移植端口 contract 应限制为 `1..65535`。

官方 URI 允许把多端口地址放入 authority，但没有定义 hop interval query key；自定义 interval 只能来自原生配置。`hopInterval=` 等 URI 参数应视为扩展，不能假设其他客户端识别。Realm URI 当前也不支持 rendezvous 地址 port hopping。

### 5. TLS、SNI、`insecure`、ALPN

| 项目 | Hysteria 2 官方行为 |
|---|---|
| SNI | query key 为 `sni`；非空时用作 TLS `ServerName`，缺失时从服务器地址取 hostname。见 [`client.go#L248-L269`](https://github.com/HyNetworks/hysteria/blob/e1366b173ccf5706e1e4630fe8aa654a4b574085/app/cmd/client.go#L248-L269)。 |
| `insecure` | 规范值为 `1` / `0`，默认 false；映射到跳过证书验证。原生 parser 使用 Go `strconv.ParseBool`，因此还宽松接受 `true/false` 等形式，但跨实现生成只应使用 `1/0`。解析失败时当前代码不更新字段，而不是报 URI 错误。 |
| ALPN | Hysteria 2 URI、`clientConfigTLS` 和 core `TLSConfig` 均无用户可配 ALPN；`alpn` query 会被原生 parser 当未知参数忽略。HTTP/3 栈自行使用 H3 ALPN。见 [`client.go#L138-L162`](https://github.com/HyNetworks/hysteria/blob/e1366b173ccf5706e1e4630fe8aa654a4b574085/app/cmd/client.go#L138-L162)、[`core/client/config.go#L103-L111`](https://github.com/HyNetworks/hysteria/blob/e1366b173ccf5706e1e4630fe8aa654a4b574085/core/client/config.go#L103-L111)。 |

Hysteria 1 与此不同：v1 URI 正式定义 `peer` 和 `alpn`，v1.3.5 默认 ALPN 是 `hysteria`，并写入 `tls.Config.NextProtos`：

- [`v1 app/cmd/config.go#L13-L30`](https://github.com/HyNetworks/hysteria/blob/57c5164854d6cfe00bead730cce731da2babe406/app/cmd/config.go#L13-L30)
- [`v1 app/cmd/client.go#L53-L59`](https://github.com/HyNetworks/hysteria/blob/57c5164854d6cfe00bead730cce731da2babe406/app/cmd/client.go#L53-L59)

因此不能把 v1 `peer` / `alpn` 原样解释成 v2 URI 字段。

### 6. Obfs

官方 URI：

```text
?obfs=salamander&obfs-password=secret
```

对应原生配置：

```yaml
obfs:
  type: salamander
  salamander:
    password: secret
```

当前 v2.12.3 还支持 `gecko`。`obfs-password` 只有在 `obfs` 为已知类型时才有意义；单独出现不能启用混淆。Salamander PSK 至少 4 bytes，未知类型报 unsupported：

- [`Full-Client-Config.md`](https://github.com/HyNetworks/hysteria-website/blob/d5c6fa441ab31b7726205ae4451f828cebe5263d/docs/docs/advanced/Full-Client-Config.md#L20-L153)
- [`extras/obfs/salamander.go`](https://github.com/HyNetworks/hysteria/blob/e1366b173ccf5706e1e4630fe8aa654a4b574085/extras/obfs/salamander.go#L13-L56)
- [`app/cmd/client.go#L335-L357`](https://github.com/HyNetworks/hysteria/blob/e1366b173ccf5706e1e4630fe8aa654a4b574085/app/cmd/client.go#L335-L357)

不支持 Gecko 的输出客户端必须明确 unsupported，不能降级成 Salamander。

### 7. Hysteria 1 / 2 快速对照

| 项目 | Hysteria 1 | Hysteria 2 |
|---|---|---|
| Scheme | `hysteria://` | `hysteria2://`、`hy2://` |
| 兼容性 | 与 v2 不兼容 | 与 v1 不兼容 |
| Auth | query `auth=` | URI userinfo |
| SNI | `peer=` | `sni=` |
| ALPN | 官方 URI 字段；原生默认 `hysteria` | 无官方用户配置字段 |
| Obfs | `xplus` + `obfsParam` | `salamander` / `gecko` + `obfs-password` |
| 带宽 | `upmbps` / `downmbps` 是 v1 URI 必填项 | v2 URI 明确不应携带 bandwidth |
| Transport | `udp` / `wechat-video` / `faketcp` | 当前原生 transport 为 UDP/HTTP3 体系 |

## 二、TUIC

### 1. 没有官方 URI 标准

当前 TUIC 仓库说明 `SPEC.md` 是 implementation-agnostic protocol specification，并明确当前没有官方实现：

- [`README.md#L20-L28`](https://github.com/tuic-protocol/tuic/blob/8e118f242f24a17a9f487dc344cc50d7e63e557e/README.md#L20-L28)
- [`SPEC.md`](https://github.com/tuic-protocol/tuic/blob/8e118f242f24a17a9f487dc344cc50d7e63e557e/SPEC.md)

在专门询问分享链接标准的官方 issue 中，维护者 EAimTY 的答复是：该格式应交给社区自行演化；协议与最小实现不包含分享链接这类非必需功能，因此不应由维护者决定格式。来源：[`tuic-protocol/tuic#209` maintainer comment](https://github.com/tuic-protocol/tuic/issues/209#issuecomment-1636147733)。

本次还核对了当前仓库、历史 v5 reference client 和 v4 client 源码；均没有 `tuic://` parser/generator。保守结论不是“任何 TUIC URI 都错误”，而是：

> `tuic://` 的 authority、userinfo、query 和编码规则都只能归属于某个明确命名的社区/client profile，不能称为 TUIC 官方 URI。

因此官方来源不能回答：

- `UUID:PASSWORD@host` 是否是标准布局；
- UUID 可否 compact、braced 或 Base64；
- password 中 `:`, `@`, `%`, Unicode 的 URL 编码；
- IPv6 authority 是否用方括号、zone ID 如何编码；
- `sni` / `allow_insecure` / `alpn` / `congestion_control` 等 query key 的名称；
- bool 是 `0/1` 还是 `true/false`；
- URI 如何区分 TUIC v4 / v5。

若本项目接收 `tuic://`，必须把上述规则记录为“本项目支持的 profile”，percent-decode 也只能依据该 profile，不能用“TUIC 官方”背书。

### 2. v5 wire spec

当前 spec 的协议版本为 `0x05`：

- Authenticate 在 wire 上是 16-byte UUID + 32-byte token；password 不直接传输；token 由当前 TLS session exporter 生成，UUID 原始 16 bytes 作 label，password 原始 bytes 作 context：[`SPEC.md#L44-L59`](https://github.com/tuic-protocol/tuic/blob/8e118f242f24a17a9f487dc344cc50d7e63e557e/SPEC.md#L44-L59)。
- 目标地址类型包括 domain、IPv4、IPv6；IPv6 是 16 bytes 后接 2-byte port：[`SPEC.md#L117-L144`](https://github.com/tuic-protocol/tuic/blob/8e118f242f24a17a9f487dc344cc50d7e63e557e/SPEC.md#L117-L144)。这证明 wire 支持 IPv6 目标，但不定义 `tuic://` authority。
- UDP relay mode 有 `native`（QUIC datagram）和 `quic`（QUIC unidirectional stream）；服务端回复沿用该 association 首包的 mode：[`SPEC.md#L170-L189`](https://github.com/tuic-protocol/tuic/blob/8e118f242f24a17a9f487dc344cc50d7e63e557e/SPEC.md#L170-L189)。
- 有 active relay task 时，client 应周期性通过 QUIC datagram 发送 Heartbeat；spec 不规定具体间隔或默认值：[`SPEC.md#L191-L193`](https://github.com/tuic-protocol/tuic/blob/8e118f242f24a17a9f487dc344cc50d7e63e557e/SPEC.md#L191-L193)。

Congestion control、0-RTT 开关、heartbeat interval、配置文件字段名都不是 wire 字段。

### 3. 历史官方 v5 reference client 配置

当前仓库已通过 [`PR #256`](https://github.com/tuic-protocol/tuic/pull/256) 移除官方实现。下表固定到移除前的 `tuic-client 1.0.0` 快照 `a299ef0`；这是历史官方实现 contract，不是 wire spec 的强制要求。

| 语义 | 历史 v5 字段 | 类型、值与默认 | Primary source |
|---|---|---|---|
| UUID | `uuid` | Rust `Uuid`；官方示例使用标准带连字符 UUID | [`tuic-client/src/config.rs#L42-L52`](https://github.com/tuic-protocol/tuic/blob/a299ef02d9f4ab5a0edbf58b9998f41bf768b332/tuic-client/src/config.rs#L42-L52)、[`README.md#L42-L46`](https://github.com/tuic-protocol/tuic/blob/a299ef02d9f4ab5a0edbf58b9998f41bf768b332/tuic-client/README.md#L42-L46) |
| Password | `password` | JSON string 解码后直接 `into_bytes()`；无 Base64/hex/URL decode，也没有 TUIC 自定义长度限制 | [`config.rs#L260-L266`](https://github.com/tuic-protocol/tuic/blob/a299ef02d9f4ab5a0edbf58b9998f41bf768b332/tuic-client/src/config.rs#L260-L266) |
| Congestion | `congestion_control` | `cubic` / `new_reno` / `bbr`；大小写不敏感，另兼容 `newreno`；默认 `cubic` | [`config.rs#L63-L67`](https://github.com/tuic-protocol/tuic/blob/a299ef02d9f4ab5a0edbf58b9998f41bf768b332/tuic-client/src/config.rs#L63-L67)、[`utils.rs#L88-L108`](https://github.com/tuic-protocol/tuic/blob/a299ef02d9f4ab5a0edbf58b9998f41bf768b332/tuic-client/src/utils.rs#L88-L108) |
| UDP relay | `udp_relay_mode` | `native` / `quic`，大小写不敏感；默认 `native` | [`utils.rs#L68-L86`](https://github.com/tuic-protocol/tuic/blob/a299ef02d9f4ab5a0edbf58b9998f41bf768b332/tuic-client/src/utils.rs#L68-L86)、[`config.rs#L174-L176`](https://github.com/tuic-protocol/tuic/blob/a299ef02d9f4ab5a0edbf58b9998f41bf768b332/tuic-client/src/config.rs#L174-L176) |
| QUIC 0-RTT | `zero_rtt_handshake` | boolean，默认 `false`；true 时尝试 `into_0rtt()`，失败回退普通握手 | [`config.rs#L75-L76`](https://github.com/tuic-protocol/tuic/blob/a299ef02d9f4ab5a0edbf58b9998f41bf768b332/tuic-client/src/config.rs#L75-L76)、[`connection/mod.rs#L283-L290`](https://github.com/tuic-protocol/tuic/blob/a299ef02d9f4ab5a0edbf58b9998f41bf768b332/tuic-client/src/connection/mod.rs#L283-L290) |
| Heartbeat | `heartbeat` | humantime duration string，默认 `3s`；只有 active TCP/UDP task 时发送 | [`config.rs#L87-L91`](https://github.com/tuic-protocol/tuic/blob/a299ef02d9f4ab5a0edbf58b9998f41bf768b332/tuic-client/src/config.rs#L87-L91)、[`handle_task.rs#L83-L100`](https://github.com/tuic-protocol/tuic/blob/a299ef02d9f4ab5a0edbf58b9998f41bf768b332/tuic-client/src/connection/handle_task.rs#L83-L100) |
| ALPN | `alpn` | string array，保持顺序，默认空 array；没有逗号字符串解析 | [`config.rs#L69-L73`](https://github.com/tuic-protocol/tuic/blob/a299ef02d9f4ab5a0edbf58b9998f41bf768b332/tuic-client/src/config.rs#L69-L73)、[`config.rs#L268-L274`](https://github.com/tuic-protocol/tuic/blob/a299ef02d9f4ab5a0edbf58b9998f41bf768b332/tuic-client/src/config.rs#L268-L274) |

TLS / 地址行为：

- `relay.server` 是 `HOST:PORT`；HOST 同时用于证书身份和 SNI，`relay.ip` 只覆盖实际拨号 IP，不覆盖 TLS identity：[`tuic-client/README.md#L36-L50`](https://github.com/tuic-protocol/tuic/blob/a299ef02d9f4ab5a0edbf58b9998f41bf768b332/tuic-client/README.md#L36-L50)、[`utils.rs#L41-L65`](https://github.com/tuic-protocol/tuic/blob/a299ef02d9f4ab5a0edbf58b9998f41bf768b332/tuic-client/src/utils.rs#L41-L65)。
- 没有独立 `server_name` override；`disable_sni` 默认 false，只关闭 SNI extension，不等于关闭证书验证：[`connection/mod.rs#L53-L65`](https://github.com/tuic-protocol/tuic/blob/a299ef02d9f4ab5a0edbf58b9998f41bf768b332/tuic-client/src/connection/mod.rs#L53-L65)。
- v5 reference client 没有 `insecure` / `allow_insecure` 字段，并用 `deny_unknown_fields` 拒绝未知字段：[`config.rs#L42-L112`](https://github.com/tuic-protocol/tuic/blob/a299ef02d9f4ab5a0edbf58b9998f41bf768b332/tuic-client/src/config.rs#L42-L112)。维护者也明确表示无计划为最小 reference implementation 加 `allow_insecure`：[`issue #176 comment`](https://github.com/tuic-protocol/tuic/issues/176#issuecomment-1578314335)。

### 4. v4 与 v5 不能混淆

| 项目 | v4 / client 0.8.5 | v5 / reference client 1.0.0 |
|---|---|---|
| Wire version | `0x04` | `0x05` |
| Auth | 单一 `token`，UTF-8 后计算 BLAKE3 digest | UUID + password，通过 TLS exporter 生成 token |
| Congestion key | `congestion_controller` | `congestion_control` |
| 0-RTT key | `reduce_rtt` | `zero_rtt_handshake` |
| Heartbeat key/default | `heartbeat_interval`，整数毫秒，默认 `10000` | `heartbeat`，duration string，默认 `3s` |
| UDP mode | `native` / `quic`，默认 native | 同名值，默认 native |

v4 来源：[`client/src/config.rs`](https://github.com/tuic-protocol/tuic/blob/0303155b28a24cd0fa2e9efa8832dd914fe74a5a/client/src/config.rs#L140-L190)、[`client/src/relay/connection.rs`](https://github.com/tuic-protocol/tuic/blob/0303155b28a24cd0fa2e9efa8832dd914fe74a5a/client/src/relay/connection.rs#L135-L228)。官方 v5 release 明确标注不兼容旧版本：[`tuic-5.0.0`](https://github.com/tuic-protocol/tuic/releases/tag/tuic-5.0.0)。

## 三、AnyTLS

### 1. 官方 URI

官方格式：

```text
anytls://[auth@]hostname[:port]/?[key=value]&[key=value]...#fragment
```

来源：[`anytls-go/docs/uri_scheme.md`](https://github.com/anytls/anytls-go/blob/fd6167acd6d73b9fa3e607659951847fbc9e6c50/docs/uri_scheme.md#L7-L50)。

| 部分 | 官方 contract |
|---|---|
| Scheme | 只有 `anytls` |
| Auth/password | 放在标准 URI username；特殊字符按 RFC 3986 percent-encode，不是 `user:password` 双字段约定 |
| Host | domain、IPv4 或 bracketed IPv6 |
| Port | 可省略；规范默认 443 |
| `sni` | TLS SNI；值为 IPv4/IPv6 literal 时客户端必须不发送 SNI |
| `insecure` | `1` = true，`0` = false |
| Fragment | 节点显示名称，发送时 percent-encode，客户端应解码 |

规范示例：

```text
anytls://p%40ss@[2001:db8::1]:443/?sni=example.com&insecure=0#Node%20A
```

注意：`p%40ss` 解码后的认证密码是 `p@ss`。若原密码包含 `:`，AnyTLS 没有 username/password 分隔语义，冒号也是密码数据，应编码为 `%3A`。

官方文档未规定：

- `sni` 缺失时的 fallback；
- `insecure` 缺失时的默认；
- `true/false`、非法值、重复 query 的处理；
- ALPN、session 或 padding 的 URI 参数；
- IPv6 zone identifier 的可移植表示；
- canonical query 顺序、是否省略默认端口。

文档允许第三方扩展参数，但明确不能假设其他实现理解。因此 `alpn=`、`idle-session-timeout=`、`padding=` 等都不是 AnyTLS 标准分享字段。

### 2. 官方样例 parser 与规范的偏差

`anytls-go` README 把自身称为参考实现，同时说明 `cmd/client` / `cmd/server` 只是用于展示协议与边界场景的示例：[`readme.md`](https://github.com/anytls/anytls-go/blob/fd6167acd6d73b9fa3e607659951847fbc9e6c50/readme.md#L1-L43)。其 URI parser 位于 [`cmd/client/main.go`](https://github.com/anytls/anytls-go/blob/fd6167acd6d73b9fa3e607659951847fbc9e6c50/cmd/client/main.go#L21-L95)，并不完整：

| 项目 | URI 文档 | `cmd/client` 实际行为 |
|---|---|---|
| Password | percent-decode username 后作为原密码 | 使用 `serverURL.User.String()`，得到重新 percent-encoded 的 userinfo，而不是 `Username()` |
| 默认端口 | 缺失时 443 | 不补端口，随后 `net.SplitHostPort`，所以实际必须显式 `:port` |
| `sni` | 标准参数 | 唯一读取的 query 参数 |
| `insecure` | `0/1` | 完全忽略；TLS 始终 `InsecureSkipVerify: true` |
| Fragment | 应 URL-decode 为显示名 | 不读取 |
| ALPN | 未定义 | `tls.Config` 不设置 `NextProtos` |

Go `net/url` 在 parse userinfo 时先解码，而 `Userinfo.String()` 再转义；解码后的值应通过 `Username()` 取得：[`Go 1.24 net/url/url.go#L407-L432`](https://github.com/golang/go/blob/go1.24.0/src/net/url/url.go#L407-L432)、[`#L580-L613`](https://github.com/golang/go/blob/go1.24.0/src/net/url/url.go#L580-L613)。所以：

```text
URI                 anytls://p%40ss@example.com:443
规范认证密码         p@ss
样例 parser 实际值   p%40ss
```

应以官方 URI 文档定义规范 parser；不能把样例缺陷解释成“密码不应 URL-decode”或“insecure 默认 true”。为了兼容该样例客户端而输出链接时，至少显式写端口；特殊字符密码仍无法同时满足文档规范和该样例 parser 的当前行为，应报告实现兼容限制。

### 3. Session 配置、默认值与语义

协议文档的逻辑字段名是：

```text
password
idleSessionCheckInterval
idleSessionTimeout
minIdleSession
paddingScheme        // server only
```

来源：[`docs/protocol.md#L209-L223`](https://github.com/anytls/anytls-go/blob/fd6167acd6d73b9fa3e607659951847fbc9e6c50/docs/protocol.md#L209-L223)。协议文档没有为三个 session 参数规定 normative default；文中的 “例如每 30s 检查、关闭空闲超过 60s” 是流程示例，不是默认值。

不同官方层次的实际值：

| 层次 | check interval | idle timeout | min idle | 说明 |
|---|---:|---:|---:|---|
| `anytls-go` 样例客户端 | `30s` | `30s` | `5` | 显式传值，见 [`cmd/client/myclient.go#L21-L26`](https://github.com/anytls/anytls-go/blob/fd6167acd6d73b9fa3e607659951847fbc9e6c50/cmd/client/myclient.go#L21-L26) |
| `anytls-go` session pool 零值/过小值 | `<=5s` → `30s` | `<=5s` → `30s` | 原值；零值为 `0` | [`proxy/session/client.go#L44-L67`](https://github.com/anytls/anytls-go/blob/fd6167acd6d73b9fa3e607659951847fbc9e6c50/proxy/session/client.go#L44-L67) |
| `sing-anytls` official library | 同上 | 同上 | 原值；零值为 `0` | [`client.go#L19-L45`](https://github.com/anytls/sing-anytls/blob/479cb5bd490a2f4b1b6e8cd82b821afb392a94c8/client.go#L19-L45)、[`session/client.go#L42-L76`](https://github.com/anytls/sing-anytls/blob/479cb5bd490a2f4b1b6e8cd82b821afb392a94c8/session/client.go#L42-L76) |

`minIdleSession` 是清理时的保留下限，不是池大小上限，也不会主动预建连接：已过期 session 在满足下限前会被保留并重置 idle time，其余才关闭。实际关闭时间落在 timeout 之后的某个检查周期。清理实现：[`anytls-go/proxy/session/client.go#L201-L241`](https://github.com/anytls/anytls-go/blob/fd6167acd6d73b9fa3e607659951847fbc9e6c50/proxy/session/client.go#L201-L241)。

不存在 `maxIdleSession`：协议参数表、`anytls-go` pool、`sing-anytls.ClientConfig` 均无此字段，也没有硬性 idle pool 最大数量。不得用 `minIdleSession` 伪装成 max。

`paddingScheme` 是服务器配置，并通过 session settings/update 命令协商给客户端，不是分享 URI 或客户端 session query：[`docs/protocol.md#L79-L155`](https://github.com/anytls/anytls-go/blob/fd6167acd6d73b9fa3e607659951847fbc9e6c50/docs/protocol.md#L79-L155)。

## 四、sing-box 与 Mihomo 的官方字段

### 1. 地址、IPv6 与 TLS 共性

两边配置都把 host 和 port 分开。`server` 应是裸 hostname/IP；IPv6 建议写成不带方括号的地址，由 client 与端口组合：

```json
{ "server": "2001:db8::1", "server_port": 443 }
```

```yaml
server: "2001:db8::1"
port: 443
```

sing-box 通过 `ServerOptions` / `ParseSocksaddrHostPort` 构造地址；Mihomo 三个 adapter 都使用 `net.JoinHostPort`，会自行给 IPv6 加方括号。不要把 `[IPv6]:port` 整体塞入 `server`，也不要预先给 Mihomo 的 `server` 加方括号：

- sing-box：[`option/outbound.go`](https://github.com/SagerNet/sing-box/blob/1ac1a339cb1223e9c70eae14c44411c75033c02d/option/outbound.go)
- Mihomo：[`hysteria2.go`](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/adapter/outbound/hysteria2.go)、[`tuic.go`](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/adapter/outbound/tuic.go)、[`anytls.go`](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/adapter/outbound/anytls.go)

TLS 字段：

| 语义 | sing-box | Mihomo |
|---|---|---|
| 启用 | 这些 outbound 都要求 `tls.enabled: true` | 协议 adapter 隐式使用 TLS，无嵌套 `tls` 开关 |
| SNI/证书名 | `tls.server_name` | `sni` |
| 跳过验证 | `tls.insecure` | `skip-cert-verify` |
| ALPN | `tls.alpn` string array | `alpn` string array |

`server_name` / `sni` 缺失时，两边通常回退到 `server`；IP 值不发送 SNI extension，但仍可用于证书 IP SAN 验证。`insecure` / `skip-cert-verify` 的零值为 false。ALPN 是有序列表；双方都支持 ALPN 且无交集时握手失败：

- sing-box [`shared/tls.md`](https://github.com/SagerNet/sing-box/blob/1ac1a339cb1223e9c70eae14c44411c75033c02d/docs/configuration/shared/tls.md)、[`common/tls/std_client.go`](https://github.com/SagerNet/sing-box/blob/1ac1a339cb1223e9c70eae14c44411c75033c02d/common/tls/std_client.go)
- Mihomo [`tls.en.md`](https://github.com/MetaCubeX/Meta-Docs/blob/517f4c2303aae17eee681129bde6422e9f7a4e67/docs/config/proxies/tls.en.md)

### 2. Hysteria 1 字段

| 语义 | sing-box v1.14.1 | Mihomo v1.19.31 |
|---|---|---|
| Plain auth | `auth_str` | `auth-str` |
| Base64 auth | `auth` | 官方文档未列出等价字段 |
| 带宽 | `up_mbps`, `down_mbps`（整数 Mbps） | `up`, `down`（数值无单位时按 Mbps） |
| XPlus password | `obfs` | `obfs` |
| Transport | sing-box outbound 不暴露 v1 `wechat-video` / `faketcp` | `protocol: udp|wechat-video|faketcp` |
| TLS | `tls` | `sni`, `skip-cert-verify`, `alpn` |

URI `auth` 是 plain string，因此进入 `auth_str`；不得放入 sing-box 的 Base64 `auth`。`obfs=xplus` 的 mode 不需要写入目标配置，`obfsParam` 才是两端 `obfs` 字段承载的密码。非 UDP transport 输出到 sing-box 必须明确 unsupported，不能降级为 UDP。

官方字段来源：sing-box [`hysteria.md`](https://github.com/SagerNet/sing-box/blob/1ac1a339cb1223e9c70eae14c44411c75033c02d/docs/configuration/outbound/hysteria.md)、Mihomo [`hysteria.en.md`](https://github.com/MetaCubeX/Meta-Docs/blob/517f4c2303aae17eee681129bde6422e9f7a4e67/docs/config/proxies/hysteria.en.md)。

### 3. Hysteria 2 字段

| 语义 | sing-box v1.14.1 | Mihomo v1.19.31 |
|---|---|---|
| 单端口 | `server_port` | `port` |
| 跳跃端口 | `server_ports: ["20000:30000"]` | `ports: 20000-30000,31000,32000-33000` |
| 固定 interval | `hop_interval: "30s"` | `hop-interval: 30`（秒） |
| 随机 interval | `hop_interval` + `hop_interval_max` | `hop-interval: "15-30"`（整数秒） |
| Auth | `password` | `password` |
| Obfs type/password | `obfs.type`, `obfs.password` | `obfs`, `obfs-password` |
| Gecko size | `obfs.min_packet_size`, `obfs.max_packet_size` | `obfs-min-packet-size`, `obfs-max-packet-size` |
| ECH config | `tls.ech.config`，必须是 `ECH CONFIGS` PEM | `ech-opts: { enable: true, config: <Base64> }` |

官方字段来源：

- sing-box [`hysteria2.md`](https://github.com/SagerNet/sing-box/blob/1ac1a339cb1223e9c70eae14c44411c75033c02d/docs/configuration/outbound/hysteria2.md)、[`option/hysteria2.go`](https://github.com/SagerNet/sing-box/blob/1ac1a339cb1223e9c70eae14c44411c75033c02d/option/hysteria2.go)、[`protocol/hysteria2/outbound.go`](https://github.com/SagerNet/sing-box/blob/1ac1a339cb1223e9c70eae14c44411c75033c02d/protocol/hysteria2/outbound.go)
- Mihomo [`hysteria2.en.md`](https://github.com/MetaCubeX/Meta-Docs/blob/517f4c2303aae17eee681129bde6422e9f7a4e67/docs/config/proxies/hysteria2.en.md)、[`adapter/outbound/hysteria2.go`](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/adapter/outbound/hysteria2.go)

转换细节：

- sing-box range 使用 `start:end`，端点包含；单端口范围要写 `443:443`，bare `443` 会被 parser 拒绝。见 [`sing-quic/hysteria/client.go::ParsePorts`](https://github.com/SagerNet/sing-quic/blob/4ab2eceaac81e073f53b22ec72ff56aaea89a3d1/hysteria/client.go)。
- Mihomo `ports` 接受 singleton 或 inclusive `N-M`，以 `/` 或 `,` 分隔；超过 28 个 split segment 会报错：[`common/utils/ranges.go`](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/common/utils/ranges.go)。
- 两边 hop 默认均为 30s、最小 5s。sing-box Duration 可表达非整秒；Mihomo 只能整数秒，不能无损承载 sub-second duration。sing-box interval source：[`sing-quic/hysteria/hop.go`](https://github.com/SagerNet/sing-quic/blob/4ab2eceaac81e073f53b22ec72ff56aaea89a3d1/hysteria/hop.go)；Mihomo normalization 在 [`hysteria2.go`](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/adapter/outbound/hysteria2.go)。
- Hysteria 2 native URI 的 multi-port `443,5000-6000` 必须解析后重新序列化，不能直接放进 sing-box `server_ports`。
- 两个 client 的 Hysteria 2 实现都在未显式设置 ALPN 时补 `h3`；这仍是 client TLS behavior，不会使 `alpn=` 成为 Hysteria 2 官方 URI 参数：[`SagerNet/sing-quic/hysteria2/client.go`](https://github.com/SagerNet/sing-quic/blob/4ab2eceaac81e073f53b22ec72ff56aaea89a3d1/hysteria2/client.go)、[`MetaCubeX/sing-quic/hysteria2/client.go`](https://github.com/MetaCubeX/sing-quic/blob/1c242664697a/hysteria2/client.go)。
- Hysteria URI 的 `ech` 是 raw ECHConfigList 的标准 Base64。Mihomo [`adapter/outbound/ech.go`](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/adapter/outbound/ech.go) 直接 Base64-decode `ech-opts.config`；sing-box [`common/tls/ech.go`](https://github.com/SagerNet/sing-box/blob/1ac1a339cb1223e9c70eae14c44411c75033c02d/common/tls/ech.go) 要求唯一的 `ECH CONFIGS` PEM block。本项目 canonical 采用 sing-box-like PEM lines；Mihomo adapter 再提取并规范化其中的 Base64 body。

### 4. TUIC 字段

| 语义 | sing-box v1.14.1 | Mihomo v1.19.31 |
|---|---|---|
| v5 auth | `uuid`, `password` | `uuid`, `password` |
| v4 auth | 无 `token` 字段 | `token`；非空时选择 v4 |
| Congestion | `congestion_control` | `congestion-controller` |
| UDP relay | `udp_relay_mode` | `udp-relay-mode` |
| QUIC 0-RTT | `zero_rtt_handshake` | `reduce-rtt` |
| Heartbeat/keepalive | `heartbeat`，Duration | `heartbeat-interval`，整数毫秒 |

来源：

- sing-box [`tuic.md`](https://github.com/SagerNet/sing-box/blob/1ac1a339cb1223e9c70eae14c44411c75033c02d/docs/configuration/outbound/tuic.md)、[`option/tuic.go`](https://github.com/SagerNet/sing-box/blob/1ac1a339cb1223e9c70eae14c44411c75033c02d/option/tuic.go)、[`protocol/tuic/outbound.go`](https://github.com/SagerNet/sing-box/blob/1ac1a339cb1223e9c70eae14c44411c75033c02d/protocol/tuic/outbound.go)
- Mihomo [`tuic.en.md`](https://github.com/MetaCubeX/Meta-Docs/blob/517f4c2303aae17eee681129bde6422e9f7a4e67/docs/config/proxies/tuic.en.md)、[`adapter/outbound/tuic.go`](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/adapter/outbound/tuic.go)

行为与默认：

| 字段 | sing-box | Mihomo |
|---|---|---|
| Congestion | 文档枚举 `cubic`, `new_reno`, `bbr`；默认 `cubic` | 文档枚举同三项但不承诺默认；空/未知值在当前源码不设置 controller，锁定的 quic-go 初始化为 Reno mode。为稳定转换应显式输出文档枚举。见 [`congestion.go`](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/transport/tuic/common/congestion.go)、[`quic-go sent_packet_handler.go`](https://github.com/MetaCubeX/quic-go/blob/2548683b76f4/internal/ackhandler/sent_packet_handler.go)。 |
| UDP relay | `native` / `quic`；默认 native | `quic` 映射 QUIC stream，空值和其他值当前落到 native；只应生成文档枚举 |
| 0-RTT | bool，零值 false | `reduce-rtt` bool，零值 false，进入 early dial path |
| Heartbeat | `sing-quic` 零值回退 `10s`，发送 TUIC heartbeat datagram | `<=0` 回退 `10000ms`；adapter 把它设置为 QUIC `KeepAlivePeriod`，不是 TUIC spec 对 heartbeat cadence 的规范证明 |
| ALPN | TUIC implementation 不主动补固定 ALPN | `alpn` 为 nil 时补 `h3`；显式空 array 保持空 |

sing-box 默认来源：[`SagerNet/sing-quic/tuic/client.go`](https://github.com/SagerNet/sing-quic/blob/4ab2eceaac81e073f53b22ec72ff56aaea89a3d1/tuic/client.go)。Mihomo 默认和映射见 [`adapter/outbound/tuic.go`](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/adapter/outbound/tuic.go)。

TLS 不能机械映射历史 official client：

- sing-box / Mihomo 都提供 SNI override 和 skip-verify；它们是各自客户端字段，不是 TUIC URI 标准。
- 历史 official v5 `disable_sni=true` 只关闭 SNI extension，不关闭验证；Mihomo 当前 `disable-sni=true` 会清空 TLS `ServerName` 并强制 `InsecureSkipVerify=true`。二者语义不同，不能按同名字段无损复制。
- Mihomo v4 `token` 节点不能无损输出成 sing-box TUIC；必须明确 unsupported，不能塞进 `password`。
- sing-box `udp_over_stream` 是额外 UoT extension，与 TUIC `udp_relay_mode: quic` 不是同一概念，并被标为冲突。

### 5. AnyTLS 字段

| 语义 | sing-box v1.14.1 | Mihomo v1.19.31 |
|---|---|---|
| Password | `password`，required | `password` |
| Check interval | `idle_session_check_interval`，Duration，默认 `30s` | `idle-session-check-interval`，整数秒，默认 `30` |
| Idle timeout | `idle_session_timeout`，Duration，默认 `30s` | `idle-session-timeout`，整数秒，默认 `30` |
| Minimum idle | `min_idle_session`，默认 `0` | `min-idle-session`，默认 `0` |
| Maximum idle | 不存在 | 不存在 |

来源：

- sing-box [`anytls.md`](https://github.com/SagerNet/sing-box/blob/1ac1a339cb1223e9c70eae14c44411c75033c02d/docs/configuration/outbound/anytls.md)、[`option/anytls.go`](https://github.com/SagerNet/sing-box/blob/1ac1a339cb1223e9c70eae14c44411c75033c02d/option/anytls.go)、[`protocol/anytls/outbound.go`](https://github.com/SagerNet/sing-box/blob/1ac1a339cb1223e9c70eae14c44411c75033c02d/protocol/anytls/outbound.go)
- Mihomo [`anytls.en.md`](https://github.com/MetaCubeX/Meta-Docs/blob/517f4c2303aae17eee681129bde6422e9f7a4e67/docs/config/proxies/anytls.en.md)、[`adapter/outbound/anytls.go`](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/adapter/outbound/anytls.go)、[`transport/anytls/session/client.go`](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/transport/anytls/session/client.go)

两者都沿用 official session pool 规则：interval / timeout `<=5s` 会回退为 `30s`；`min` 是保留下限，不是上限。转换时必须做 Duration 与整数秒的单位转换，非整秒 sing-box Duration 无法无损输出到 Mihomo。

Mihomo 官方文档明确 AnyTLS + Reality 不支持且不计划支持；带 Reality 的 sing-box AnyTLS outbound 不能宣称可无损转换到 Mihomo。官方建议使用 ECH、ShadowTLS、ResTLS、JLS，或在必须用 Reality 时换用其他协议：[`anytls.en.md`](https://github.com/MetaCubeX/Meta-Docs/blob/517f4c2303aae17eee681129bde6422e9f7a4e67/docs/config/proxies/anytls.en.md)。

## 五、有限 unsupported 与 parser/builder 边界

| 输入或转换 | 正确处理 | 不应做的伪兼容 |
|---|---|---|
| `hysteria://...` | 交给独立 Hysteria 1 parser | 当作 `hysteria2://` |
| Hysteria 2 URI `alpn=` | 标记为未知扩展；若项目选择兼容需明确 profile | 声称是 Hysteria 2 官方字段 |
| Hysteria 2 URI 自定义 hop interval | 官方 URI 无此字段；仅 multi-port authority 可移植 | 把任意 `hopInterval` query 当标准 |
| Hysteria 2 Gecko 输出到旧客户端 | 明确版本不支持 | 静默降级为 Salamander |
| `tuic://...` | 按明确命名的本地/客户端 profile 解析，并记录其 encoding 与版本判别 | 声称 UUID/password、bool、SNI query 是 TUIC 官方 URI 规范 |
| TUIC v4 token → sing-box | unsupported | 把 token 塞进 v5 password/UUID |
| TUIC `disable_sni` | 逐客户端核对证书验证副作用 | 仅凭同名字段直接复制 |
| AnyTLS URI `alpn` / session / padding | 扩展参数；默认不假设互通 | 当作 AnyTLS 官方 share-link 字段 |
| AnyTLS `maxIdleSession` | unsupported；两客户端均无字段 | 用 `minIdleSession` 模拟 |
| AnyTLS + Reality → Mihomo | unsupported | 丢掉 Reality 后声称等价 |
| Hysteria 2 port list → sing-box/Mihomo | 解析为离散 range model 后按目标语法重新序列化 | 原字符串跨格式复制 |
| Duration → Mihomo 整数秒 | 仅完整秒可无损；否则报告 loss/unsupported | 静默截断 sub-second 值 |

URI parser 的最低安全/互通 contract：

1. userinfo percent-decode 恰好一次；malformed `%` escape 失败，不保留半解码值。
2. IPv6 必须使用 URL authority parser 处理方括号，不能用第一次 `:` 拆 host/port。
3. 端口限制为十进制 `1..65535`；不要依赖底层 `uint16` 接受 `0` 的宽松实现。
4. 官方只定义 `0/1` 的 URI bool 时，生成固定使用 `0/1`；不要使用 JavaScript truthiness 解释任意非空字符串。
5. 区分“规范字段缺失”和“显式 false”。尤其 AnyTLS URI 没有规定 `insecure` 缺失默认，样例客户端行为不能补写该规范。
6. 客户端配置字段可以表达比分享 URI 更多的 TLS/session 能力；这种能力不反向扩张上游 URI 标准。

## 六、本项目采用的解析 contract

以下是基于上述官方来源制定的本项目输入 profile，不把兼容扩展冒充成上游标准。

### Hysteria 1

- `hysteria://` 单独交给 v1 parser，端口及 `upmbps` / `downmbps` 必填；带宽只接受可无损进入目标配置的正整数 Mbps。
- `protocol` 缺失时为 `udp`；接受官方 `udp`、`wechat-video`、`faketcp`，并兼容 v1 源码中的 `wechat` alias。不能表示所选 transport 的目标客户端由 builder 明确拒绝。
- URI `auth` 是普通字符串，进入 canonical `auth_str`，不能误作 v2 `password` 或 Base64 `auth`。
- `peer`、`insecure`、`alpn` 进入 canonical `tls`；ALPN 缺失时显式保留 v1 默认 `hysteria`。
- `obfs=xplus&obfsParam=...` 进入 canonical `obfs` 密码字符串；未知 obfs 或缺密码直接失败。

### Hysteria 2

- 只接受 `hysteria2://` / `hy2://`；`hysteria://` 必须交给 v1 parser。
- 按官方语义 percent-decode userinfo 一次，支持无 auth、默认端口 443、bracketed IPv6，以及 authority 内 `443,5000-6000` 形式的 port hopping。
- `insecure` 只接受官方 `0/1`；`pinSHA256` 规范化为 64 位小写证书 SHA-256。官方 `ech` 先规范化为 canonical `ECH CONFIGS` PEM lines；Mihomo adapter 提取 Base64 body 写入 `ech-opts`，没有等价字段的目标明确拒绝。
- `obfs` 只接受 `salamander` / `gecko`，必须同时有 `obfs-password`；Gecko packet-size query 是目标客户端兼容扩展，不属于官方 URI。
- 为兼容现有 Mihomo 分享源，继续接受 `mport` / `ports`、`hop-interval` / `hop_interval` 与随机 interval aliases；它们经过范围和单位校验后进入内部对象，不宣称为 Hysteria 2 官方 URI 字段。
- v1 的 `auth`、`peer`、`alpn`、`upmbps`、`downmbps` 不映射进 v2 对象。若链接试图仅靠 v1 `auth` 认证，或仅靠 `peer` 提供证书名，parser 明确失败；附带在已有 v2 auth / `sni` 后的冗余 v1 字段则忽略，避免生成看似可用但语义错误的节点。

### TUIC v5 项目 profile

本项目接受的非官方 profile 是：

```text
tuic://UUID:PASSWORD@HOST:PORT?[options]#NAME
```

- 第一个未转义 `:` 是 UUID/password 分隔符，两部分各 percent-decode 一次；password 内的 `:`, `@`, `%` 必须编码。UUID 使用 canonical hyphenated text；host 支持 bracketed IPv6；端口必须显式给出。
- 无 `:` 的 `token@host` 是 v4-shaped link，明确 unsupported，不能冒充 v5。
- 接受 `congestion_control` / `congestion-controller`，值限 `cubic`, `new_reno`, `bbr`；缺失时显式用 `cubic`，避免 sing-box 与 Mihomo 空值行为不同。
- 接受 `udp_relay_mode` / `udp-relay-mode`，值限 `native`, `quic`；缺失时用 `native`。
- 0-RTT aliases 统一为内部 `zero_rtt_handshake`；`heartbeat` 使用可无损换算成整数毫秒的 duration，`heartbeat-interval` / `heartbeat_interval` 按毫秒解释并转成 duration。未提供 heartbeat 时不伪称某个 TUIC wire 默认。
- TLS aliases 统一到 `tls.server_name`, `tls.insecure`, `tls.alpn`, `tls.disable_sni`；bool 仅接受 `0/1/true/false`。输出 Mihomo 时必须额外处理 `disable_sni=true` 的证书验证副作用，不能仅按同名字段复制。

### AnyTLS

- 官方字段按 URI 文档解析：username 是完整 password，percent-decode 一次；无端口时 443；IPv6 使用方括号；`sni` / `insecure` 和 fragment 保留。
- 为兼容既有客户端链接，额外接受 ALPN、`fp` / `client-fingerprint` uTLS 指纹、whole-certificate `fingerprint`、UDP 和三个 session 参数 aliases；这些是本项目兼容扩展，不是 AnyTLS 官方 URI。bare `fingerprint` 不得误作浏览器 uTLS 指纹。
- Session duration 扩展以整数秒为输入，要求非负安全整数；`min-idle-session` 同样要求非负整数。这样可在 sing-box Duration 与 Mihomo 整数秒字段间无损转换。`max-idle-session` 明确拒绝，因为 official library、sing-box、Mihomo 均不存在等价字段。
- AnyTLS URI 没有定义 ECH / REALITY 参数格式；本项目不猜测这些扩展的编码，遇到已知参数时明确拒绝。完整 sing-box AnyTLS + Reality 配置转 Mihomo 同样属于 unsupported。
- malformed percent escape、重复/冲突 alias、非法 bool、非法端口或不可表示的已知字段直接失败，不生成部分解码或静默降级的配置。
