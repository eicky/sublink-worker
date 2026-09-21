# 客户端协议字段合同核对（截至 2026-09-20）

> 状态：研究结论定稿；仅记录合同与缺陷，不包含实现改动。
>
> 项目基线：`sublink-worker` `2.4.2`，Git commit [`3361ad72630bbd328a0a01c49f553aaa985889c3`](https://github.com/eicky/sublink-worker/tree/3361ad72630bbd328a0a01c49f553aaa985889c3)。本文按该 Git 对象核对，不把工作区中未提交内容当作基线。
>
> 工作树说明：本次研究期间有其他 Agent 并发修改解析器与 builder，因此第 4 节的缺陷状态特指上述固定基线；部分项目已在未提交工作树中开始修复。第 3、5、7 节的客户端合同与能力边界仍是合并验收依据，最终应以固定版本真实客户端 schema 检查重新判定。

## 结论先行

1. 当前所谓“内部对象”不是稳定的 canonical model。URI、Clash YAML、Surge INI 与原生 sing-box JSON 对同一语义使用不同位置、名称和类型；`BaseConfigBuilder` 又把它们都直接交给三个 builder。因此同一节点仅因输入格式不同，就会得到不同输出。
2. 有两项会降低证书校验的高影响缺陷：公共 URI TLS helper 把字符串 `"0"`/`"false"` 当成 `true`；TUIC URI 在未给任何 insecure 参数时默认 `tls.insecure=true`。
3. `hysteria://` 是 Hysteria v1 分享格式，不是 Hysteria 2 别名。当前却把它交给 Hysteria2 parser；官方明确 v1/v2 不兼容。
4. `ClashConfigBuilder` 的真实合同应定义为 **Mihomo/Clash.Meta**，不是 classic Clash。VLESS、Hysteria2、TUIC、AnyTLS、Reality 等不能仅靠切换 rule-set 格式就兼容旧 Clash。
5. 当前 Surge 能使用 AnyTLS，但 builder 仍把它输出为“不支持”；TUIC v5 则错误输出成 Surge 的 v4 类型 `tuic`。
6. 原生 sing-box 订阅没有被规范化：SS `plugin_opts`、Hysteria2 端口/带宽/Duration、TUIC 0-RTT、AnyTLS Duration、`network` 与 `packet_encoding` 都会在跨客户端或同客户端往返中丢失/错型。
7. 不存在统一的“所有协议 URI 标准”。SS SIP002、Hysteria v1 归档 URI、Hysteria 2 URI、AnyTLS URI 各有项目级合同；SSR 是停更生态的历史 dialect；VLESS 与 authority-style VMessAEAD 属于持续演进的 Xray proposal；VMess Base64(JSON) 是 v2rayN dialect，扩展 Trojan URI、TUIC URI 也都不能写成冻结的通用标准。

---

## 1. 审计版本与证据边界

| 对象 | 截至 2026-09-20 的固定基线 | 说明 |
|---|---|---|
| sing-box | [`v1.14.1`](https://github.com/SagerNet/sing-box/releases/tag/v1.14.1)，2026-09-15，commit `1ac1a339…` | 字段合同以该 tag 的 [`option/`](https://github.com/SagerNet/sing-box/tree/v1.14.1/option) 与官方配置文档为准。`v1.15.0-alpha.*` 是 prerelease，不作为稳定合同。 |
| Mihomo | [`v1.19.31`](https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.31)，2026-09-14，commit `ab405bad…` | 字段合同以该 commit 的 outbound struct 和 Meta-Docs `517f4c2303…` 为准。 |
| Surge | Mac `6.9.0`（Build 12250，2026-08-31）；[iOS App Store version history](https://apps.apple.com/us/app/surge-5/id1442620678)当前为 `5.22.1` | Surge 手册是 rolling 文档，没有可固定 tag；以下能力以 2026-09-20 访问的[官方手册](https://manual.nssurge.com/policies/overview.html)和[官方 Mac release notes](https://nssurge.com/support/mac/release-notes)为准。 |
| Hysteria 1 | 最终版 [`v1.3.5`](https://github.com/HyNetworks/hysteria/releases/tag/v1.3.5)，现为 legacy | 分享链接以官方 v1 归档文档为准；不得用 v2 规范反推。 |
| Hysteria 2 | [`app/v2.12.3`](https://github.com/HyNetworks/hysteria/releases/tag/app/v2.12.3) | URI 与端口跳跃以官方 v2 文档/源码为准。 |
| AnyTLS | [`anytls-go v0.0.13`](https://github.com/anytls/anytls-go/releases/tag/v0.0.13) | URI 只保证 `sni`、`insecure`，其余 query 是实现扩展。 |
| TUIC | wire protocol `0x05` | 官方 [`SPEC.md`](https://github.com/tuic-protocol/tuic/blob/master/SPEC.md)不定义 `tuic://` 分享 URI。 |
| VLESS/Xray | Xray-core [`v26.3.27`](https://github.com/XTLS/Xray-core/releases/tag/v26.3.27)；libXray [`v26.9.9`](https://github.com/XTLS/libXray/releases/tag/v26.9.9) | 分享链接依据 Xray-core [Discussion #716](https://github.com/XTLS/Xray-core/discussions/716)，其标题和正文仍是 proposal。 |
| VMess/V2Ray | V2Fly [`v5.53.0`](https://github.com/v2fly/v2ray-core/releases/tag/v5.53.0)；v2rayN `7.24.9`；Xray-core `v26.3.27` | `vmess://Base64(JSON)` 是 [v2rayN 约定](https://github.com/2dust/v2rayN/wiki/Description-of-VMess-share-link)；Xray-core [Discussion #716](https://github.com/XTLS/Xray-core/discussions/716)另定义 authority-style VMessAEAD proposal。二者都不是已冻结的 V2Fly 通用 URI 标准。 |

证据优先级：目标版本源码/官方协议规范 > 官方配置手册 > 官方项目 proposal。没有用第三方博客推导字段。

---

## 2. 实际调用路径与内部合同现状

当前路径是：

```text
BaseConfigBuilder.parseCustomItems()
  ├─ URI → ProxyParser → src/parsers/protocols/*Parser.js
  ├─ Clash YAML → parseClashYaml → convertYamlProxyToObject
  ├─ Surge INI → parseSurgeIni → convertSurgeProxyToObject
  └─ sing-box JSON → parseSingboxJson → 原样取出 outbounds（不规范化）

addCustomItems()
  └─ ClashConfigBuilder / SingboxConfigBuilder / SurgeConfigBuilder.convertProxy()
```

代码证据：[`ProxyParser.js`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/parsers/ProxyParser.js#L10-L35)、[`subscriptionContentParser.js`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/parsers/subscription/subscriptionContentParser.js#L22-L55)、[`convertYamlProxyToObject.js`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/parsers/convertYamlProxyToObject.js#L1-L264)、[`convertSurgeProxyToObject.js`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/parsers/convertSurgeProxyToObject.js#L51-L203)、[`BaseConfigBuilder.js`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/builders/BaseConfigBuilder.js#L30-L180)。

### 2.1 基线 URI parser 的实际输出

| Parser | 基线返回字段（省略值为 `undefined` 的可选项） | 重要边界 |
|---|---|---|
| `parseShadowsocks` | `tag,type,server,server_port,method,password,tcp_fast_open,plugin,plugin_opts` | `plugin_opts` 已被改写为 Mihomo 风格 object，不再是原始 SIP003 string。 |
| `parseVmess` | `tag,type,server,server_port,uuid,alter_id,security,tcp_fast_open,transport,tls?` | 只接受 v2rayN Base64(JSON) dialect，authority-style proposal 会解析失败；只构造 WS/HTTP/gRPC/H2，不读取 `alpn`、`fp`、Reality、UDP 或官方 `insecure`，且扩展 `skip-cert-verify` 仍用 JS truthiness。 |
| `parseVless` | `type,tag,server,server_port,uuid,tcp_fast_open,tls,transport,flow,udp?` | Reality 时固定 uTLS Chrome；非 `type=tcp` 一律构造通用 transport，缺 `type` 也会产生空对象。 |
| `parseTrojan` | `type,tag,server,server_port,password,tcp_fast_open,tls,transport,flow` | 强制默认 TLS，但公共 TLS helper 不读 ALPN/fingerprint，且缺 `type` 时会产生空 transport。 |
| `parseHysteria2` | `tag,type,server,server_port,password,tls,obfs,auth,recv_window_conn,up,down,ports,hop_interval,alpn,fast_open` | authority 中的 port union 未保留；`ports` 只读 query 扩展。`hysteria://` 也被错误派发到这里。 |
| `parseTuic` | `tag,type,server,server_port,uuid,password,congestion_control,tls,flow,udp_relay_mode,zero_rtt,reduce_rtt,fast_open,disable_sni` | URI 是 de facto dialect；缺省 `tls.insecure=true`；decoded password 中第二个 `:` 之后会丢失。 |
| `parseAnytls` | `tag,type,server,server_port,password,udp?,idle-session-*,min-idle-session,tls` | 官方 URI 只保证 `sni/insecure`；ALPN/fingerprint/UDP/idle query 均是扩展。 |

Clash YAML converter 试图输出类似 sing-box 的对象，但混入 Mihomo 根级 `alpn`、`udp`、kebab-case session 字段；Surge converter也输出类似对象，却只覆盖官方 Surge 字段的一小部分。原生 sing-box JSON 则完全不经过上述规范化。

### 2.2 当前内部对象的同名异义/异名同义

| 语义 | URI/Clash 转换常见形态 | 原生 sing-box 形态 | builder 当前假设 | 后果 |
|---|---|---|---|---|
| ALPN | VMess/VLESS/Trojan/Hysteria2 常在根级 `alpn`；TUIC/AnyTLS 在 `tls.alpn` | `tls.alpn` | Singbox builder 会部分搬移；Clash/Surge 各自读取不同位置 | 输入来源决定 ALPN 是否丢失。 |
| `network` | Mihomo 中是 V2Ray transport 名；converter 也会写 `tcp` | sing-box 中是允许的 L4 网络列表 `tcp`/`udp` | Singbox builder 无条件删除；Clash VMess/Trojan 又把它当 transport | UDP 限制丢失，甚至生成 `network: udp` 这类错误 Mihomo transport。 |
| UDP | Mihomo 为 `udp: bool` | 多数 sing-box outbound 用 `network` allowlist；AnyTLS 没有同名开关 | Singbox builder直接删除 `udp` | `udp:false` 会被变成 sing-box 默认的 TCP+UDP。 |
| SS plugin | parser/YAML 为 `plugin_opts: object` | `plugin_opts: string` | 两边直接透传 | 至少一个目标类型必错。 |
| Hysteria2 hopping | `ports`、`hop_interval` 秒/秒区间、`up/down` | `server_ports`、Duration、`hop_interval_max`、`up_mbps/down_mbps` | 只处理部分 kebab/share-link 形态 | 原生 sing-box → Mihomo/Surge 和 Mihomo 区间 → sing-box 均不完整。 |
| TUIC 0-RTT | Mihomo `reduce-rtt` | sing-box `zero_rtt_handshake` | Clash builder还会发出不存在的 `zero-rtt` | 同一能力无法往返。 |
| AnyTLS idle | Mihomo 整数秒 | sing-box Duration 字符串 | URI/YAML 数字 → sing-box 已转换；反向不转换 | 原生 sing-box → Mihomo 出现 `"30s"`→`int` 类型错误。 |
| transport | Mihomo 有独立 `h2`；HTTP path 常为数组 | sing-box 无 `h2` discriminator；HTTP path 是字符串 | 直接透传 | `sing-box check` 会拒绝 `h2`、空 transport 或 path 数组。 |

正确的边界合同应先把四类输入规范化为与客户端无关的语义值，再由每个 builder 序列化；不能把某个客户端的配置对象当作通用中间格式。

---

## 3. 简明 contract 矩阵

### 3.1 协议与目标客户端

| 协议 | sing-box 1.14.1 | Mihomo 1.19.31（`ClashConfigBuilder` 实际目标） | Surge 当前版 | 分享 URI 的规范地位 |
|---|---|---|---|---|
| Shadowsocks | 支持；`plugin_opts` 是字符串；内建 SIP003 plugin 仅 `obfs-local`、`v2ray-plugin`。见[官方文档](https://sing-box.sagernet.org/configuration/outbound/shadowsocks/)和 [`option/shadowsocks.go`](https://github.com/SagerNet/sing-box/blob/v1.14.1/option/shadowsocks.go)。 | 支持；`plugin-opts` 是 map；当前支持 `obfs`、`v2ray-plugin`、`gost-plugin`、`shadow-tls`、`restls`、`kcptun`、`jls`。见[文档](https://wiki.metacubex.one/en/config/proxies/ss/)和 [`shadowsocks.go`](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/adapter/outbound/shadowsocks.go)。 | 支持；通用 plugin 不存在，只提供 `obfs=http` / `obfs=tls`、`obfs-host`、`obfs-uri`。SS UDP 需 `udp-relay=true`。见[SS 手册](https://manual.nssurge.com/policies/shadowsocks.html)。 | [SIP002](https://shadowsocks.org/doc/sip002.html) 是官方项目规范。 |
| ShadowsocksR | **不支持**；1.5.0 deprecated，1.6.0 完全移除。见[官方 deprecated 列表](https://sing-box.sagernet.org/deprecated/)。 | 支持 `type:ssr`；核心字段为 `cipher/password/protocol/protocol-param/obfs/obfs-param/udp`。见[文档](https://wiki.metacubex.one/en/config/proxies/ssr/)和 [`shadowsocksr.go`](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/adapter/outbound/shadowsocksr.go)。 | **不支持**；当前官方 policy 类型列表没有 `ssr`/`shadowsocksr`，不能降级成普通 SS。 | `ssr://` 是已停更生态的历史 QR-code 方言，不属于 Shadowsocks SIP002；必须明确所接受的 dialect。 |
| VMess | 支持；TLS、packet encoding、V2Ray transport。见[文档](https://sing-box.sagernet.org/configuration/outbound/vmess/)。 | 支持；TLS/uTLS/Reality、UDP 与多种 transport。见[文档](https://wiki.metacubex.one/en/config/proxies/vmess/)。 | 支持；官方只列 TCP/WS，TLS 可选；`encrypt-method`、`vmess-aead` 有专门语义；UDP 自动支持。见[手册](https://manual.nssurge.com/policies/vmess.html)。 | 无完成的统一标准：`vmess://Base64(JSON)` 是 v2rayN dialect；Xray #716 另有 authority-style VMessAEAD proposal，固定 AEAD/`alter_id=0`，仍允许 breaking change。 |
| VLESS | 支持 `flow`、TLS/Reality、transport 与 packet encoding；没有新版 VLESS `encryption` 字段，非 `none` 必须拒绝。见[文档](https://sing-box.sagernet.org/configuration/outbound/vless/)。 | 支持 `flow`、TLS/Reality、transport、packet encoding 以及当前 native/xorpub + X25519/ML-KEM `encryption` 语法。见[文档](https://wiki.metacubex.one/en/config/proxies/vless/)。 | **不支持**；官方 policy 列表无 VLESS。 | Xray [Discussion #716](https://github.com/XTLS/Xray-core/discussions/716) 是 canonical proposal，不是 IETF/最终通用标准。 |
| Trojan | 支持；TLS 与 V2Ray transport。见[文档](https://sing-box.sagernet.org/configuration/outbound/trojan/)。 | 支持；TLS 隐式，transport 只认 WS/gRPC，Reality 可用。见[文档](https://wiki.metacubex.one/en/config/proxies/trojan/)和 [`trojan.go`](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/adapter/outbound/trojan.go)。 | 支持；TLS 隐式，官方只列 TCP/WS，UDP 自动支持。见[手册](https://manual.nssurge.com/policies/trojan.html)。 | 官方组织的 [`trojan-url`](https://github.com/trojan-gfw/trojan-url)明确写着“not finalized”；只定义最小 `password@host:port`。 |
| Hysteria v1 | 支持；`server_ports`/`hop_interval` 自 1.12，带宽可用带单位字符串或整数 Mbps；只支持原生 QUIC 形态，Mihomo 的 `wechat-video`/`faketcp` transport 无同构。见[文档](https://sing-box.sagernet.org/configuration/outbound/hysteria/)和 [`option/hysteria.go`](https://github.com/SagerNet/sing-box/blob/v1.14.1/option/hysteria.go)。 | 支持 `port/ports`、整数秒 `hop-interval`、`auth`/`auth-str`、带宽、obfs，以及 `protocol:udp` / `protocol:wechat-video` / `protocol:faketcp`。见[文档](https://wiki.metacubex.one/en/config/proxies/hysteria/)和 [`hysteria.go`](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/adapter/outbound/hysteria.go)。 | **不支持**；当前官方 policy 类型列表只有 Hysteria2。 | `hysteria://` 有[官方 v1 URI 文档](https://v1.hysteria.network/docs/uri-scheme/)；host/port/upmbps/downmbps 必填，`protocol` 缺省 `udp`，可选 `udp` / `wechat-video` / `faketcp`，`auth` 是 query 参数，`peer` 是 SNI，ALPN 缺省 `hysteria`，obfs 形态为 `xplus` + `obfsParam`。v1/v2 不兼容。 |
| Hysteria2 | 支持；`server_ports` 自 1.11，随机 hopping 上界与 `realm` 自 1.14。见[文档](https://sing-box.sagernet.org/configuration/outbound/hysteria2/)。 | 支持；当前支持 salamander/gecko（含 Gecko min/max packet size）、秒区间 hopping 与 `realm-opts`。见[文档](https://wiki.metacubex.one/en/config/proxies/hysteria2/)。 | 支持；iOS 5.8.0+/Mac 5.4.0+，有独立 hopping、带宽、`salamander-password`/`gecko-password`；当前手册无 Gecko packet-size 或 Realm 字段。见[手册](https://manual.nssurge.com/policies/hysteria2.html)。 | `hysteria2://`、`hy2://` 及 `hysteria2+realm://`/`hysteria2+realm+http://` 有[官方 v2 URI 规范](https://v2.hysteria.network/docs/developers/URI-Scheme/)；`hysteria://` 属于 v1。 |
| TUIC | 只提供 UUID/password 的 v5 形态。见[文档](https://sing-box.sagernet.org/configuration/outbound/tuic/)和 [`option/tuic.go`](https://github.com/SagerNet/sing-box/blob/v1.14.1/option/tuic.go)。 | 同一 `type: tuic` 下，`token` 选择 v4，UUID/password 选择 v5；二者不可混用。见[文档](https://wiki.metacubex.one/en/config/proxies/tuic/)和 [`tuic.go`](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/adapter/outbound/tuic.go)。 | v4=`tuic`+`token`；v5=`tuic-v5`+UUID/password，两种 type 不可互换。见[手册](https://manual.nssurge.com/policies/tuic.html)。 | 官方 wire spec 不定义 `tuic://`；所有 URI 参数均应标为实现方言。 |
| AnyTLS | 自 1.12 支持；idle 时间是 Duration；`client_metadata` 自 1.13.16。见[文档](https://sing-box.sagernet.org/configuration/outbound/anytls/)。 | 自 `v1.19.3` 支持；idle 时间是整数秒；官方明确不支持 Reality。见[文档](https://wiki.metacubex.one/en/config/proxies/anytls/)和 [`anytls.go`](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/adapter/outbound/anytls.go)。 | 支持 AnyTLS v2；iOS 5.17.0+/Mac 6.4.3+；`reuse` 是唯一 session-reuse 开关，UDP 自动通过 TCP。见[手册](https://manual.nssurge.com/policies/anytls.html)。 | [官方 URI](https://github.com/anytls/anytls-go/blob/v0.0.13/docs/uri_scheme.md)只规定 `sni`、`insecure`。 |

### 3.2 TLS / uTLS / Reality / ALPN

| 语义 | sing-box | Mihomo | Surge |
|---|---|---|---|
| TLS 容器 | `tls: { enabled, server_name, insecure, alpn, utls, reality }` | 大多平铺；VMess/VLESS 用 `tls`; Trojan/Hysteria v1/Hysteria2/TUIC/AnyTLS 的 TLS 属于协议固有行为 | 平铺；VMess 用 `tls=true`; Trojan/Hysteria2/TUIC/AnyTLS 隐式 TLS |
| SNI | `tls.server_name` | VMess/VLESS 常为 `servername`; Trojan/Hysteria v1/Hysteria2/TUIC/AnyTLS 为 `sni` | `sni`; `sni=off` 可关闭发送 SNI |
| 跳过校验 | `tls.insecure` | `skip-cert-verify` | `skip-cert-verify` |
| ALPN | `tls.alpn: string[]` | 顶层 `alpn: string[]` | `alpn=h2`；多项必须作为一个带引号的逗号列表，例如 `alpn="h2,http/1.1"`，见[TLS 手册](https://manual.nssurge.com/policies/tls.html) |
| uTLS | TCP 型兼容 TLS outbound 可用 `tls.utls`；自 1.10；`apple`/`windows` TLS engine 不支持；QUIC 只支持 ECH，所以 Hysteria v1/Hysteria2/TUIC 不支持 uTLS。见[shared TLS](https://sing-box.sagernet.org/configuration/shared/tls/) | VMess/VLESS/Trojan/AnyTLS 的 `client-fingerprint`；Hysteria v1/Hysteria2/TUIC option struct 没有该能力 | 官方 policy 参数没有 uTLS client fingerprint |
| Reality | `tls.reality` 仅可用于实现支持的 TCP TLS outbound；Hysteria v1/Hysteria2/TUIC 等 QUIC outbound 不支持；native Apple/Windows TLS engine 不支持 | VMess/VLESS/Trojan 支持；AnyTLS 明确不支持，Hysteria v1/Hysteria2/TUIC 也没有该字段 | 官方 policy 参数没有 Reality；必须拒绝而不是静默退化成普通 TLS |
| ECH | `tls.ech`；QUIC 只允许 ECH，不允许 uTLS/Reality；显式 config 使用 `ECH CONFIGS` PEM 行 | `ech-opts`；Hysteria v1/Hysteria2/TUIC/AnyTLS 等目标 struct 可携带 Base64 config 或做 DNS discovery | 当前官方 policy 参数未列 ECH；不能静默丢弃 |

Surge profile quoting 合同：policy 参数值含逗号时必须加双引号，例如 `password="a,b"`、`alpn="h2,http/1.1"`。当前版本（iOS 5.21+/Mac 6.8+）在双引号值中用 `\"` 表示字面双引号、`\\` 表示反斜线，见[官方 Profile Format](https://manual.nssurge.com/profile/format.html)和[Policy Overview](https://manual.nssurge.com/policies/overview.html)。`ws-headers` 只规范为 `Header:Value|Header2:Value2`；官方没有定义 header 值内部 `|` 的逃逸规则，出现歧义字符时应拒绝，不能发明私有转义。

### 3.3 transport 合同

| 目标 | VMess | VLESS | Trojan | 关键结构 |
|---|---|---|---|---|
| sing-box | `http`、`ws`、`quic`、`grpc`、`httpupgrade` | 同左 | 同左 | `http.host` 为 string/list、`http.path` 为 string；WS `headers.Host`；gRPC `service_name`；HTTPUpgrade 有独立 `type:httpupgrade`。**没有 `type:h2`**。见 [`v2ray_transport.go`](https://github.com/SagerNet/sing-box/blob/v1.14.1/option/v2ray_transport.go)。 |
| Mihomo | `ws`、`http`、`h2`、`grpc`、`mkcp`、`mekya` | `ws`、`http`、`h2`、`grpc`、`xhttp` | 仅 `ws`、`grpc` | `network:http` 是 legacy TCP HTTP-header camouflage；`network:h2` 才对应 sing-box 的真实 HTTP/H2 transport。HTTPUpgrade 不是独立 network，而是 `network: ws` + `ws-opts.v2ray-http-upgrade`；HTTP path 是 list，H2 host 是 list。见[transport 文档](https://wiki.metacubex.one/en/config/proxies/transport/)。 |
| Surge | TCP、WS | 不支持协议 | TCP、WS | WS 用 `ws=true`、`ws-path`、`ws-headers`；官方没有 VMess/Trojan gRPC/HTTP/H2 参数。 |

因此：不能原样传递 transport `type`；仅 Mihomo `h2 ↔` sing-box `http`，Mihomo `network:http` 的一次性 TCP HTTP-header camouflage **不能**映射为 sing-box 的真实 HTTP body transport；`httpupgrade ↔ ws-opts flag` 也需要显式 serializer。目标不支持的 transport 必须拒绝。

Wire 证据：Xray [`headers/http/http.go`](https://github.com/XTLS/Xray-core/blob/main/transport/internet/headers/http/http.go)只在首个双向 write 加/剥一次 HTTP header，随后是裸 TCP；sing-box [`transport/v2rayhttp/client.go`](https://github.com/SagerNet/sing-box/blob/v1.14.1/transport/v2rayhttp/client.go)则用真实 HTTP request/response body，无 TLS 时为 HTTP/1.1，有 TLS 时通过 `http2.Transport.RoundTrip` 建立 HTTP/2 stream。字段看似相近但 wire 不兼容。Mihomo [`vmess.go`](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/adapter/outbound/vmess.go)、[`vless.go`](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/adapter/outbound/vless.go)也没有 `network:httpupgrade` case：未知值会静默走 TCP，只有 `network:ws` 时才读取 `ws-opts.v2ray-http-upgrade`。因此 `mihomo -t` 接受未知 discriminator 不能证明能力。

### 3.4 UDP、端口跳跃、Duration 与插件

| 能力 | sing-box | Mihomo | Surge |
|---|---|---|---|
| 通用 UDP | 多数 outbound 的 `network` 是 `tcp`/`udp` allowlist；省略表示两者；不是 V2Ray transport 名 | `udp: bool` 通常默认 false；TUIC 等 UDP-oriented 类型例外 | SS 需 `udp-relay=true`; VMess/Trojan/TUIC/Hysteria2/AnyTLS 自动支持；VLESS 不存在 |
| Hysteria v1 hopping ports | 1.12+ `server_ports:["443:443","8443:8445"]`；与 `server_port` 互斥 | `ports:"443,8443-8445"`，同时保留 primary `port` | 不支持协议 |
| Hysteria v1 hopping interval | `hop_interval:"30s"` Duration；目标默认 30s | `hop-interval:30` 整数秒；目标默认 10s | 不支持协议 |
| Hysteria2 hopping ports | `server_ports: ["443:443", "8443:8445"]`; 范围用冒号 | `ports: "443,8443-8445"`（也接受 `/` 分隔）；范围用连字符 | `port-hopping=443;8443-8445`; 多段用分号 |
| Hysteria2 hopping interval | `hop_interval:"15s"`, 1.14 可加 `hop_interval_max:"30s"`; Duration，最小 5s | `hop-interval:15` 或 `"15-30"`; 整数秒 | `port-hopping-interval=15`; 整数秒 |
| TUIC port hopping | 当前 outbound schema 无同构字段 | 当前 outbound schema 无同构字段 | `port-hopping` + `port-hopping-interval`；与 `underlying-proxy` 冲突 |
| AnyTLS idle | `idle_session_check_interval:"30s"`, `idle_session_timeout:"30s"`, `min_idle_session:0` | kebab-case；前两项为整数秒，第三项为整数 | 没有三个同构字段；只有 `reuse=true` / `reuse=false`，不可假称无损映射 |
| AnyTLS reuse | 无直接布尔同构字段 | `disable-reuse` | `reuse`，与 Mihomo 字段逻辑相反 |
| TUIC 0-RTT | `zero_rtt_handshake` | `reduce-rtt` | 官方手册未给等价开关 |
| TUIC heartbeat | `heartbeat` Duration；0 回落 10s | `heartbeat-interval` 毫秒；<=0 回落 10000ms | 无同构字段 |
| SS plugin | `plugin` + **字符串** `plugin_opts` | `plugin` + **map** `plugin-opts` | 只提供平铺 simple-obfs 字段 |

Hysteria2 细节证据：sing-box [pinned docs](https://github.com/SagerNet/sing-box/blob/1ac1a339cb1223e9c70eae14c44411c75033c02d/docs/configuration/outbound/hysteria2.md)、Mihomo [pinned docs](https://github.com/MetaCubeX/Meta-Docs/blob/517f4c2303aae17eee681129bde6422e9f7a4e67/docs/config/proxies/hysteria2.en.md)；TUIC/AnyTLS 对应的 [sing-box TUIC](https://github.com/SagerNet/sing-box/blob/1ac1a339cb1223e9c70eae14c44411c75033c02d/docs/configuration/outbound/tuic.md)、[sing-box AnyTLS](https://github.com/SagerNet/sing-box/blob/1ac1a339cb1223e9c70eae14c44411c75033c02d/docs/configuration/outbound/anytls.md)、[Mihomo TUIC](https://github.com/MetaCubeX/Meta-Docs/blob/517f4c2303aae17eee681129bde6422e9f7a4e67/docs/config/proxies/tuic.en.md)、[Mihomo AnyTLS](https://github.com/MetaCubeX/Meta-Docs/blob/517f4c2303aae17eee681129bde6422e9f7a4e67/docs/config/proxies/anytls.en.md)。

---

## 4. 沿真实调用路径确认的缺陷（按影响排序）

### P0-1：`insecure=0` / `allowInsecure=false` 被反转为跳过证书校验

- 虚构输入：

  ```text
  trojan://p@edge.example:443?security=tls&type=tcp&sni=edge.example&insecure=0#safe
  ```

- 路径：`parseTrojan` → `createTlsConfig` → 任一 builder。
- 当前错误：`createTlsConfig` 使用 `!!params.insecure`；字符串 `"0"` 和 `"false"` 都是 truthy，因此内部得到 `tls.insecure=true`。随后 sing-box 输出 `insecure:true`，Mihomo 输出 `skip-cert-verify:true`，Surge 输出 `skip-cert-verify=true`。
- 正确预期：只有显式 `1`/`true` 才启用 insecure；`0`/`false` 与缺省都必须是 false。非法布尔值应拒绝或按未设置处理，不能用 JS truthiness。该 helper 还完全不读 `skip-cert-verify`，所以接受该扩展名的输入会发生相反方向的静默丢失。
- 证据：项目 [`utils.js#L289-L309`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/utils.js#L289-L309)；三个客户端的证书跳过字段见上文 TLS 表。

### P0-2：TUIC URI 缺省即关闭证书校验

- 虚构输入（实现方言；TUIC 没有官方 URI 标准）：

  ```text
  tuic://00000000-0000-0000-0000-000000000001:pwd@edge.example:443?alpn=h3#safe
  ```

- 当前错误：`parseTuic` 对 `skip-cert-verify/insecure/allowInsecure` 都缺省时调用 `parseBool(..., true)`，得到 `tls.insecure=true`。
- 正确预期：缺省必须校验证书；只有显式 insecure 才关闭。若无法确认方言合同，应拒绝含糊输入，而不是选择不安全默认。
- 证据：[`tuicParser.js#L7-L29`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/parsers/protocols/tuicParser.js#L7-L29)。

### P1-1：把 `hysteria://`（v1）误当 Hysteria2

- 虚构输入：

  ```text
  hysteria://old.example:443?protocol=udp&auth=secret&upmbps=20&downmbps=100#v1
  ```

- 当前错误：`ProxyParser` 将 `hysteria`、`hysteria2`、`hy2` 全部派发给 `parseHysteria2`，最终输出 `type:hysteria2`。
- 正确预期：`hysteria://` 必须由独立 v1 parser 处理，并严格要求 host/port/upmbps/downmbps；`protocol` 缺省为 `udp`，只接受 `udp` / `wechat-video` / `faketcp`（源码还兼容 `wechat` alias）。`auth` 规范化为 `auth_str`，`peer` 为 TLS SNI，ALPN 缺省 `hysteria`，`obfs=xplus&obfsParam=...` 保留为 v1 obfs。sing-box 1.14.1 与 Mihomo 1.19.31 均支持 Hysteria v1（包括各自的 port hopping 结构），Surge 当前不支持时拒绝；Hysteria2 只接受 `hysteria2://`/`hy2://`。
- 证据：项目 [`ProxyParser.js#L10-L21`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/parsers/ProxyParser.js#L10-L21)；Hysteria v1 [官方归档 URI Scheme](https://v1.hysteria.network/docs/uri-scheme/)；官方 v2 parser 只接受两种 v2 scheme（[`client.go#L518-L620`](https://github.com/HyNetworks/hysteria/blob/e1366b173ccf5706e1e4630fe8aa654a4b574085/app/cmd/client.go#L518-L620)）；官方说明 [v1/v2 不兼容](https://github.com/HyNetworks/hysteria-website/blob/d5c6fa441ab31b7726205ae4451f828cebe5263d/docs/docs/misc/2-vs-1.md#L1-L20)。

### P1-2：官方 Hysteria2 URI 的 port hopping 被截成单端口

- 虚构输入：

  ```text
  hy2://secret@edge.example:443,8443-8445/?sni=edge.example&insecure=0#hop
  ```

- 当前错误：通用 `parseServerInfo` 对端口文本调用 `parseInt`，得到 `server_port=443`；`ports` 仅从 query 的非标准 `mport/ports` 读取，因此 `8443-8445` 全丢。另一个合法输入 `hy2://secret@edge.example/?sni=edge.example` 省略端口时，官方应默认 443，当前却得到 `server_port=NaN`。
- 正确预期：解析 authority 中的完整 port union；省略端口使用 443；sing-box 序列化为 `server_ports:["443:443","8443:8445"]`，Mihomo 为 `ports:"443,8443-8445"`，Surge 为 `port-hopping=443;8443-8445`。
- 证据：项目 [`utils.js#L255-L269`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/utils.js#L255-L269) 与 [`hysteria2Parser.js#L3-L49`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/parsers/protocols/hysteria2Parser.js#L3-L49)；官方[端口跳跃语法](https://github.com/HyNetworks/hysteria-website/blob/d5c6fa441ab31b7726205ae4451f828cebe5263d/docs/docs/advanced/Port-Hopping.md#L7-L51)。

### P1-3：SS URI dialect 分支与 delimiter 解析错误

- 合法 SIP002 明文 userinfo（2022 密钥仅作示例）：

  ```text
  ss://2022-blake3-aes-128-gcm:MDEyMzQ1Njc4OWFiY2RlZg%3D%3D@ss.example:8388/#node
  ```

  当前有 `@` 时仍无条件把 userinfo 当 Base64 解码；`method` 变成二进制乱码，`password` 为空或错误。SIP002 Stream/AEAD 可用 Base64URL 或 percent-encoded 明文；AEAD-2022 **MUST NOT** Base64URL-encode userinfo，必须走 `method:password` 明文分支。

- 合法 legacy whole-Base64 URI：

  ```text
  ss://YWVzLTI1Ni1nY206cEBzczp3QHNzLmV4YW1wbGU6ODM4OA#legacy
  ```

  解码为 `aes-256-gcm:p@ss:w@ss.example:8388`，password 是 `p@ss:w`。基线先用 `.split('@')`，再用 `.split(':')`，会把含 `@`/`:` 的密码和 endpoint 截断。正确解析应以最后一个 `@` 分 credential/endpoint，并只用 credential 中第一个 `:` 分 method/password；随后严格校验完整 host/port，而不是宽松截取。

- 两个分支都需做完整 Base64URL、percent-decoding、IPv6 authority 与 port 校验，不能靠 delimiter 数量猜 dialect。
- 证据：项目 [`shadowsocksParser.js#L85-L129`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/parsers/protocols/shadowsocksParser.js#L85-L129) 与 [`utils.js#L71-L93`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/utils.js#L71-L93)；官方 [SIP002](https://shadowsocks.org/doc/sip002.html)及旧整串 Base64 形态的 [`configs.md`](https://github.com/shadowsocks/shadowsocks-org/blob/main/docs/doc/configs.md)。

### P1-4：SS plugin 的名称、结构和转义无法跨三个客户端

- 虚构输入（官方 SIP002 形态）：

  ```text
  ss://YWVzLTEyOC1nY206c2VjcmV0@ss.example:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dcdn.example#obfs
  ```

- 当前错误：parser 把 option 改写成 Clash 风格 object，却只把 `simple-obfs` 归一化为 `obfs`，不处理常见 `obfs-local`：
  - sing-box 收到 object 型 `plugin_opts`，但 schema 要 string；
  - Mihomo 收到 `plugin:obfs-local`，但实现识别的是 `obfs`，且 native sing-box 的字符串 `plugin_opts` 反向输入又会被原样放进 map 字段；
  - Surge builder 完全丢弃 plugin/obfs。
- 正确预期：内部保留原始 SIP003 option string 或无损语义 AST；每个目标单独序列化。Surge 只可转换 simple-obfs，其他 plugin 必须拒绝。SIP002 对 `;`、`=`、`:`、`\` 还有反斜杠转义规则，当前 `split(';')` 也不满足。
- 同一路径还缺 cipher capability check。例如 `2022-blake3-chacha20-poly1305` 可用于 sing-box/Mihomo，但 Surge 官方当前只列两种 AES-2022 cipher；当前 builder 会原样发出，正确行为是拒绝该 Surge 节点。
- 证据：项目 [`shadowsocksParser.js#L11-L81`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/parsers/protocols/shadowsocksParser.js#L11-L81)、三个 builder；客户端结构见上文 SS 行及 Surge [SS 手册](https://manual.nssurge.com/policies/shadowsocks.html)。

### P1-5：transport 未规范化，产生空 transport、非法 `h2` 和错型 HTTP path

具体输入与结果：

| 虚构输入 | 当前错误 | 正确预期 |
|---|---|---|
| `vless://00000000-0000-0000-0000-000000000001@edge:443?security=tls&sni=edge#tcp-default`（无 `type`） | `params.type !== 'tcp'` 成立，创建 `{type:undefined}`；JSON 后成为 `transport:{}`，sing-box 因缺少 discriminator 拒绝 | 缺省为 TCP，应完全省略 `transport` |
| Clash VMess：`network:h2, h2-opts:{host:[edge],path:/x}` | sing-box 输出 `transport.type:"h2"` | 转成 sing-box `type:"http"` 的等价结构，不能原样透传 |
| VMess JSON：`net:"quic", type:"none"` 且无额外 QUIC option → sing-box | parser 未构造 transport，节点静默退化为 TCP | canonical 保留 plain `quic`；sing-box v1.14.1 仅支持空 QUIC transport options。v2rayN 方言的 QUIC security/key/header 扩展不可表示时拒绝；Mihomo/Surge 目标也拒绝 |
| Clash VMess：`network:http, http-opts.path:[/a,/b]` | 若映成 sing-box `transport.type:http`，不仅 path 类型不匹配，还会把一次性 TCP HTTP-header camouflage 变成真实 HTTP request/body transport | sing-box 没有同构的 legacy TCP HTTP 伪装，必须拒绝；不得选 path 后降级为 `type:http` |
| VLESS proposal：`type=httpupgrade&host=edge&path=/u` → Mihomo | builder 输出不支持的 `network:httpupgrade`，且无 `ws-opts.v2ray-http-upgrade` | 映射成 Mihomo `network:ws` + HTTPUpgrade flags；不能表达则拒绝 |
| VLESS proposal：`type=xhttp&host=edge&path=/x&mode=packet-up` → Mihomo | parser/builder没有完整 `xhttp-opts`，mode/extra 等静默丢失或被拒绝 | Mihomo VLESS 支持 `network:xhttp` + `xhttp-opts`，应专门序列化；sing-box 1.14/Surge 目标拒绝 |
| Mihomo：`network:ws, ws-opts:{v2ray-http-upgrade:true,path:/u}` → 其他目标 | converter只看 `network:ws`，把 HTTPUpgrade 静默变成普通 WebSocket | WS 分支必须识别 upgrade flag，规范化为 `httpupgrade` 并保留 path/headers/fast-open |
| Mihomo VLESS：`encryption:"mlkem768x25519plus.native.1rtt.100-111-1111.75-0-111.50-0-3333.MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="` | `convertYamlProxyToObject` 不读取 `encryption`，即使目标仍为 Mihomo也静默退化为未启用；sing-box 目标则没有该字段 | Mihomo 目标无损保留；sing-box 1.14.1/Surge 明确拒绝非空、非 `none` encryption |
| `trojan://...&flow=xtls-rprx-vision` → sing-box/Mihomo | parser保存 `flow`，两个 builder继续发出，但目标版本 Trojan schema 都没有该字段 | 对这些目标明确拒绝该扩展，不能靠未知字段被忽略 |
| VMess/Trojan gRPC → Surge | builder发出手册未定义的 `grpc-service-name`，客户端不会因此使用 gRPC | 明确拒绝该节点/transport |

- 证据：项目 [`vlessParser.js`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/parsers/protocols/vlessParser.js)、[`utils.js#L312-L320`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/utils.js#L312-L320)、[`convertYamlProxyToObject.js#L25-L177`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/parsers/convertYamlProxyToObject.js#L25-L177)；客户端 transport schema 见 3.3。

### P1-6：标准 Mihomo Trojan YAML 被转换成 `tls.enabled:false`

- 虚构输入：

  ```yaml
  proxies:
    - name: t
      type: trojan
      server: edge.example
      port: 443
      password: p
      sni: edge.example
  ```

- 当前错误：Mihomo Trojan TLS 是隐式的，官方 struct 没有要求 `tls:true`；converter 却用 `!!p.tls`，于是内部为 `tls.enabled:false`。目标 sing-box 得到被关闭的 TLS，节点不可用。
- 正确预期：Trojan 输入默认/强制 TLS；只有协议明确支持的安全层配置才可改变它，不能从缺少 Mihomo `tls` 键推导为 false。
- 证据：项目 [`convertYamlProxyToObject.js#L126-L177`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/parsers/convertYamlProxyToObject.js#L126-L177)；Mihomo [`TrojanOption`](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/adapter/outbound/trojan.go)与[官方文档](https://wiki.metacubex.one/en/config/proxies/trojan/)。

### P1-7：Surge TUIC v5 被标成 v4；真实 Surge TUIC 输入也解析错

- 虚构内部节点：

  ```json
  {"type":"tuic","tag":"t","server":"edge.example","server_port":443,"uuid":"00000000-0000-0000-0000-000000000001","password":"p"}
  ```

- 当前错误：Surge builder 输出 `t = tuic, ..., uuid=00000000-0000-0000-0000-000000000001, password=p`。Surge 的 `tuic` 是 v4，要求 `token`; v5 必须是 `tuic-v5`。它还发出 Surge 手册未定义的 Mihomo 字段 `congestion-controller`、`udp-relay-mode`。反向上，`convertSurgeProxyToObject` 不识别 `tuic-v5`，并把 `tuic` 当 UUID/password 形态，真实 v4/v5 都不能可靠导入；Surge TUIC 的 `port-hopping`/`port-hopping-interval` 也完全未保留。
- 正确预期：明确携带 TUIC version/auth union；v4=`tuic, token=...`，v5=`tuic-v5, uuid=..., password=...`。sing-box 不支持 v4 或 TUIC port hopping 时必须拒绝/明确有损，不能静默改成单端口。
- 证据：项目 [`SurgeConfigBuilder.js#L113-L130`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/builders/SurgeConfigBuilder.js#L113-L130)、[`convertSurgeProxyToObject.js#L150-L166`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/parsers/convertSurgeProxyToObject.js#L150-L166)；Surge [TUIC 手册](https://manual.nssurge.com/policies/tuic.html)。

### P1-8：Surge 已支持 AnyTLS，但节点被输出成注释并从组中消失

- 虚构输入（符合 AnyTLS 项目 URI 最小合同）：

  ```text
  anytls://pwd@edge.example:443/?sni=edge.example&insecure=0#at
  ```

- 当前错误：`SurgeConfigBuilder` 没有 `anytls` case，生成 `# at - Unsupported proxy type: anytls`；`getValidProxies()` 又把注释排除，所以节点不进入任何 group。反向输入真实 Surge 行 `at = anytls, edge.example, 443, password=pwd` 时，`convertSurgeProxyToObject` 也没有 case，整节点被丢弃。
- 正确预期：至少输出/解析 `at = anytls, edge.example, 443, password=pwd, sni=edge.example`；`insecure=1` 时附 `skip-cert-verify=true`。idle session 三字段在 Surge 没有同构字段，需显式报告有损，不能伪造。
- 证据：项目 [`SurgeConfigBuilder.js#L49-L135`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/builders/SurgeConfigBuilder.js#L49-L135)；Surge [AnyTLS 手册](https://manual.nssurge.com/policies/anytls.html)。

### P1-9：客户端版本/家族 gating 只覆盖外围配置，没有约束协议字段

- 虚构请求 A：目标 sing-box `1.11`，输入上一个 AnyTLS URI。
  - 当前：`singboxVersion` 只影响 provider/rule-set 等路径；`convertProxy` 仍发出 `type:anytls`。但 AnyTLS 自 1.12 才存在。
  - 同类：1.14 才有的 Hysteria2 `hop_interval_max`/Gecko 字段、1.13.16 才有的 AnyTLS `client_metadata`，也没有按精确目标版本 gating。
- 虚构请求 B：User-Agent `Clash/1.x`（classic Clash），输入 VLESS/TUIC/AnyTLS。
  - 当前：`supportsMrsFormat()` 只切换 rule-set 格式，proxy 节点仍按 Mihomo schema发出；旧 Clash 不会因此获得这些协议能力。
  - 正确合同：将该输出明确命名/标记为 Mihomo，或对 classic Clash 做协议 capability gating；不能把 rule-set 兼容误当 proxy schema 兼容。
- 正确预期：目标版本低于字段 introduction、或客户端家族不支持协议时明确拒绝，或做有文档依据的降级；不能输出客户端未知字段。
- 证据：项目 [`SingboxConfigBuilder.js#L16-L47`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/builders/SingboxConfigBuilder.js#L16-L47) 与 [`#L104-L179`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/builders/SingboxConfigBuilder.js#L104-L179)、[`ClashConfigBuilder.js#L11-L41`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/builders/ClashConfigBuilder.js#L11-L41)；sing-box 各字段 introduction 见 3.1/3.4，Mihomo 协议合同见 3.1。

### P1-10：原生 sing-box 订阅不做协议规范化，跨目标产生错型/丢失

`parseSingboxJson` 直接把 outbound 原对象放进 `proxies`。以下都沿真实路径可达：

| 具体虚构 sing-box outbound | 当前目标输出 | 正确预期 |
|---|---|---|
| SS：`plugin:"obfs-local", plugin_opts:"obfs=http;obfs-host=cdn"` | Mihomo `plugin-opts` 仍是 string，且 plugin 名未归一化 | 解析为 Mihomo map + `plugin:obfs`，或拒绝无法解析的 string |
| Hysteria2：`server_ports:["443:443","8443:8445"], hop_interval:"30s", up_mbps:100, obfs:{type:"gecko",password:"o",min_packet_size:512,max_packet_size:1200}` | Clash 丢 `server_ports/up_mbps`，发出 `hop-interval:"30s"`（Mihomo int parser拒绝），且只保留 obfs type/password、丢 Gecko packet-size；Surge也丢 hopping/带宽/obfs | 目标专用范围/Duration/带宽/obfs 转换 |
| TUIC：`zero_rtt_handshake:true, heartbeat:"10s"` | Clash 两字段均丢；没有 `reduce-rtt`/`heartbeat-interval` | `reduce-rtt:true, heartbeat-interval:10000`，并处理默认差异 |
| AnyTLS：`idle_session_timeout:"30s", client_metadata:"k=v"` | Clash 发出 `idle-session-timeout:"30s"`（Mihomo struct 要 int），并完全丢失当前 Mihomo也支持的 `client-metadata` | 转成 `30` 并映射 `client-metadata`；非整秒应拒绝或明确取整策略 |
| VMess：`global_padding:true, authenticated_length:true` → Clash | 两字段静默丢失 | 映射为 Mihomo `global-padding:true, authenticated-length:true` |
| VMess/VLESS：`network:"udp", packet_encoding:"packetaddr"` → sing-box | 同格式 builder 仍无条件删掉 `network` 与 `packet_encoding` | 原生字段应保留；只有来自其他 adapter 的伪 transport/network 才应被规范化 |

- 证据：项目 [`parseSingboxJson`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/parsers/subscription/subscriptionContentParser.js#L22-L49)、[`SingboxConfigBuilder.convertProxy`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/builders/SingboxConfigBuilder.js#L104-L179)、[`ClashConfigBuilder.convertProxy`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/builders/ClashConfigBuilder.js#L131-L305)。

### P1-11：UDP 允许/禁止语义在两方向都被反转

- 虚构输入 A：Clash SS 节点 `udp:false`。
  - 当前：converter 同时产生 `udp:false` 和无条件 `network:"tcp"`；sing-box builder 把两者都删掉，最终 sing-box 缺省允许 TCP+UDP。
  - 预期：显式 `udp:false` 应序列化为 sing-box `network:"tcp"`；`udp:true`/未指定才按合同选择省略或双栈。
- 虚构输入 B：原生 sing-box VMess `network:"tcp"`。
  - 当前：Clash builder默认 `udp:true`，破坏源端“仅 TCP”限制。
  - 预期：转换为 Mihomo `udp:false`；不能把 sing-box `network` 当 V2Ray transport。
- 虚构输入 C：Clash SS 节点 `udp:true` → Surge。
  - 当前：Surge builder不输出 `udp-relay=true`，而 Surge SS 的该字段默认 false。
  - 预期：显式启用 `udp-relay=true`；若源端明确 false 则保持缺省/false。
- 证据：项目 [`convertYamlProxyToObject.js#L9-L124`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/parsers/convertYamlProxyToObject.js#L9-L124)、[`SingboxConfigBuilder.js#L126-L148`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/builders/SingboxConfigBuilder.js#L126-L148)、[`ClashConfigBuilder.js#L43-L48`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/builders/ClashConfigBuilder.js#L43-L48)、[`SurgeConfigBuilder.js#L51-L54`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/builders/SurgeConfigBuilder.js#L51-L54) 与 Surge [UDP 手册](https://manual.nssurge.com/policies/udp.html)。

### P1-12：官方 Hysteria2 Realm URI 完全未进入解析链

- 虚构输入（符合当前官方 Realm URI）：

  ```text
  hysteria2+realm://token@rendezvous.example:443/my-realm?auth=user%3Apass&stun=stun1.example:3478&stun=stun2.example:3478#realm
  ```

- 当前错误：`ProxyParser` 没有注册 `hysteria2+realm` / `hysteria2+realm+http`，因此链接直接返回未支持；即使复用当前 `parseUrlParams`，`Object.fromEntries` 也会把可重复的 `stun` 压成单值。原生 sing-box Realm outbound 又与 `server` 字段互斥，而 `parseSingboxJson` 强制要求 `o.server`，所以该输入路径也会静默过滤节点。
- 正确预期：将 Realm 建模为与直连 `server/server_ports` 互斥的 tagged union，保留 rendezvous URL、token、realm name、Hysteria `auth`、全部 STUN 与 `lport`；sing-box 1.14+ 序列化为 `realm`，Mihomo 序列化为 `realm-opts`，Surge 当前不支持时明确拒绝。Realm URI 不允许 port hopping，不能退化为普通 Hysteria2 endpoint。
- 证据：官方 [Hysteria2 URI Scheme / Realm Mode](https://v2.hysteria.network/docs/developers/URI-Scheme/)、sing-box [Hysteria2 `realm`](https://sing-box.sagernet.org/configuration/outbound/hysteria2/)、Mihomo [Hysteria2 `realm-opts`](https://wiki.metacubex.one/en/config/proxies/hysteria2/)。

### P2-1：ALPN/uTLS/Reality 没有统一位置，支持能力被静默丢弃或错误降级

| 具体虚构输入 | 当前错误 | 正确预期 |
|---|---|---|
| VMess Base64 JSON 含 `alpn:"h2"`, `fp:"firefox"`, `vcn:"verify.example"`, `pcs:"<cert-sha256>"` | parser不读取这些 TLS 约束；三个输出均丢 | ALPN/fingerprint按目标保留；`vcn` 独立映射为 Mihomo `name-cert-verify` / Surge `server-cert-verify-name`；`pcs`是证书指纹，不能冒充 sing-box SPKI pin |
| v2rayN JSON 含官方 `insecure:"1"` | parser完全不读 `insecure`，把源节点要求的跳过校验静默改成校验证书，节点可能无法连接 | 按 v2rayN dialect 严格解析 `"0"` / `"1"`；缺省才是 false |
| 同一 JSON 改用项目扩展 `skip-cert-verify:"0"` | parser把字符串 `"0"` 原样放进 `tls.insecure`；Surge builder因 JS truthiness输出 `skip-cert-verify=true`，strict sing-box 则会因 bool 错型拒绝 | 方言扩展也必须先解析成 boolean；字符串 `"0"` 绝不能启用 insecure |
| VMess JSON 使用 `port:"443junk"`, `id:"not-a-uuid"`, `aid:"70000"`, `scy:"rot13"` | `parseInt` 宽松接受端口前缀，UUID/alterId/security 无格式、范围或枚举校验，错误值一直进入 builder | port 做完整十进制/范围校验；UUID、alterId 和 security 按目标 VMess dialect 严格验证 |
| VMess v2rayN 方言含 `tls:"reality", fp:"firefox", pbk:"...", sid:"..."` | parser未把 Reality key/short ID 交给 TLS canonical object，支持目标也无法生成节点 | sing-box/Mihomo VMess 支持 Reality，应按明确方言校验并保留；Surge 目标拒绝 |
| `vless://...security=reality&fp=firefox&pbk=...&sid=...&type=tcp` | parser把 fingerprint硬编码为 `chrome`，忽略 `fp=firefox` | 保留明确 fingerprint；Reality 缺必要 `fp/pbk` 时拒绝 |
| `vless://00000000-0000-0000-0000-000000000001@edge.example:443?security=tls&type=ws&host=front.example`（无 `sni`） | 公共 helper 用 transport `host` 作为 `tls.server_name` | SNI 缺省应由远端 server/客户端规则决定；WS Host 与 TLS SNI 是独立语义，不能自动等同 |
| 官方 Hysteria2 URI 含 `pinSHA256=...&ech=...` | parser不读取两项，证书 pin/ECH 静默丢失 | `pinSHA256` 是证书 SHA-256 fingerprint，不能映射为 sing-box 的证书**公钥** SHA-256；只有目标字段语义和编码完全一致时才可转换，否则拒绝。`ech` 是 Base64 ECHConfigList：Mihomo Hysteria2 可映射为 `ech-opts.enable/config`，sing-box 可包装为 `ECH CONFIGS` PEM 后写入 `tls.ech.config`；其他目标拒绝/报告有损 |
| 原生 sing-box VLESS/Trojan/Hysteria2 `tls.alpn:["h2"]` → Clash | builder这些 case读取根级 `proxy.alpn`，ALPN丢失；VMess case根本不输出 ALPN/uTLS/Reality | 统一从 canonical TLS 对象序列化 |
| 原生 sing-box VMess/Trojan Reality → Surge | builder静默去掉 Reality，输出看似普通 TLS 的节点，实际握手失败 | Surge 不支持时应把节点标为不可转换，而非降级 |
| AnyTLS + Reality → Mihomo | builder会忽略 `tls.reality` | 官方明确不支持，应拒绝 |

- 证据：项目 [`vmessParser.js`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/parsers/protocols/vmessParser.js)、[`vlessParser.js`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/parsers/protocols/vlessParser.js)、三个 builder；v2rayN [VMess share-link dialect](https://github.com/2dust/v2rayN/wiki/Description-of-VMess-share-link)；客户端支持边界见 3.2。

### P2-2：Surge 多 ALPN 和 WS header 的 INI 语法被破坏

- 虚构内部 TLS：`alpn:["h2","http/1.1"]`。
  - 当前输出：`alpn=h2,http/1.1`，第二项被 INI comma parser 当成新参数。Surge 官方要求多 ALPN 值加引号。
  - 预期：`alpn="h2,http/1.1"`，并做 INI escaping。
- 虚构合法输入：`alpn="h2,http/1.1"`。
  - 当前 `convertSurgeProxyToObject` 先无条件 `split(',')`，即使在引号内也切开，只留下错误的 `"h2`。
  - 预期：使用支持 quoted value 的 INI/tokenizer。
- 凭据：`password="a,b\"c\\d"` 在当前 Surge 版本是可表示值；逗号要求 quote，quoted value 内 `\"` 和 `\\` 分别解码成双引号与反斜线。逐字符逢 `"` 就切换 quoted 状态、或拒绝所有反斜线，都会误解析合法配置。
- WS：Surge 的 `ws-headers` 是 `Header:Value|Header2:Value2`；当前 converter 把整串当成 `host` 值，builder 又只读取小写 `headers.host`，其他 header 和大小写均丢。整个参数可以因逗号而 quote，但官方没有定义 header 值内部 `|` 的 escaping，遇到该歧义必须拒绝。
- 证据：项目 [`convertSurgeProxyToObject.js#L66-L100`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/parsers/convertSurgeProxyToObject.js#L66-L100)、[`SurgeConfigBuilder.js#L55-L130`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/builders/SurgeConfigBuilder.js#L55-L130)；Surge [Profile Format](https://manual.nssurge.com/profile/format.html)、[TLS](https://manual.nssurge.com/policies/tls.html)、[VMess](https://manual.nssurge.com/policies/vmess.html)、[Trojan](https://manual.nssurge.com/policies/trojan.html)手册。

### P2-3：Surge Hysteria2 的 hopping、obfs 与带宽全部未映射

- 虚构 Clash YAML：

  ```yaml
  - name: hy
    type: hysteria2
    server: edge.example
    port: 443
    ports: 443,8443-8445
    hop-interval: 15
    password: p
    down: 100 Mbps
    obfs: salamander
    obfs-password: o
    sni: edge.example
  ```

- 当前输出只含 `hysteria2, server, port, password, sni`；`ports`、`hop-interval`、`down`、`obfs`、`obfs-password` 均丢。反向 Surge 输入的 `port-hopping`、`port-hopping-interval`、`download-bandwidth`、`salamander-password`/`gecko-password` 也未解析。
- 正确预期：分别映射为 `port-hopping`（逗号转分号）、`port-hopping-interval`、`download-bandwidth`、对应 obfs password；无法表达的 upload/随机区间需报告有损。
- 证据：项目 [`SurgeConfigBuilder.js#L101-L112`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/builders/SurgeConfigBuilder.js#L101-L112)、[`convertSurgeProxyToObject.js#L168-L186`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/parsers/convertSurgeProxyToObject.js#L168-L186)；Surge [Hysteria2 手册](https://manual.nssurge.com/policies/hysteria2.html)。

### P2-4：Hysteria2 区间与带宽类型仅覆盖最简单情况

- 虚构 Mihomo 输入：`ports:"443/8443-8445"`, `hop-interval:"15-30"`, `up:"100 Mbps"`。
- 当前 sing-box 输出：
  - `ports` 只按逗号切分，`/` 保留并得到非法 `server_ports`；
  - `hop_interval:"15-30"` 原样进入 Duration 字段，没有生成 1.14 的 `hop_interval_max`；
  - `up_mbps:"100 Mbps"` 是字符串，schema 要整数。
- 正确预期：完整解析 Mihomo range grammar；转为 `server_ports:["443:443","8443:8445"]`、`hop_interval:"15s"`、`hop_interval_max:"30s"`、`up_mbps:100`。小数秒无法无损映射到 Mihomo整数秒时应拒绝/明确舍入。
- `convertYamlProxyToObject` 也没有读取当前 Mihomo 的 `obfs-min-packet-size`/`obfs-max-packet-size`，所以 Gecko 配置甚至在进入 builder 前已丢失。反向输出还会发出 Mihomo Hysteria2 struct 没有的 `auth`、`recv-window-conn`、`fast-open`；这些未知键可能被忽略，不能算能力支持。
- 证据：项目 [`SingboxConfigBuilder.js#L150-L176`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/builders/SingboxConfigBuilder.js#L150-L176)、[`convertYamlProxyToObject.js#L179-L210`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/parsers/convertYamlProxyToObject.js#L179-L210) 与 [`ClashConfigBuilder.js#L219-L238`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/builders/ClashConfigBuilder.js#L219-L238)；两端 pinned docs 见 3.4。

### P2-5：TUIC 名称、默认值和单位映射不成立

- 虚构 Clash TUIC：`reduce-rtt:true, heartbeat-interval:10000, congestion-controller:bbr`。
  - 当前 converter不保留 heartbeat；sing-box builder把 `reduce_rtt` 原样留下为未知字段，而不是 `zero_rtt_handshake`。
- 虚构原生 sing-box TUIC：`zero_rtt_handshake:true, heartbeat:"10s"`。
  - 当前 Clash builder不读取两者；如果内部有 `zero_rtt`，还会发出 Mihomo struct 不存在的 `zero-rtt`。
- 正确预期：`zero_rtt_handshake ↔ reduce-rtt`；Duration ↔ 毫秒；`udp_over_stream` 不得误当 `udp-relay-mode:quic`。省略 congestion/ALPN 也不是天然等价：sing-box congestion 默认 cubic、Mihomo 当前依赖默认 Reno；sing-box TUIC 不自动注入 ALPN，Mihomo缺省注入 `h3`。
- 证据：项目 [`convertYamlProxyToObject.js#L212-L233`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/parsers/convertYamlProxyToObject.js#L212-L233)、两个 builder；pinned [`option/tuic.go`](https://github.com/SagerNet/sing-box/blob/v1.14.1/option/tuic.go)与 [Mihomo `tuic.go`](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/adapter/outbound/tuic.go)。

### P2-6：Surge VMess 丢 cipher，并伪装支持 gRPC

- 虚构内部 VMess：`security:"chacha20-poly1305"`, `transport:{type:"grpc",service_name:"svc"}`。
- 当前输出：没有 Surge 必需的 `encrypt-method=chacha20-ietf-poly1305`/相应可用值，只追加手册未定义的 `grpc-service-name=svc`。Surge 会使用默认 `aes-128-gcm` 和 TCP，节点不可用。
- 反向 Surge 输入中官方键是 `encrypt-method`、`vmess-aead`；converter读取的是 `cipher/security`、`alterId`，会丢实际设置。
- 正确预期：支持的 cipher 做显式枚举映射；gRPC 节点拒绝。`vmess-aead` 与 `alter_id` 做双向、版本明确的转换。
- 证据：项目 [`SurgeConfigBuilder.js#L55-L80`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/builders/SurgeConfigBuilder.js#L55-L80)、[`convertSurgeProxyToObject.js#L117-L130`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/parsers/convertSurgeProxyToObject.js#L117-L130)；Surge [VMess 手册](https://manual.nssurge.com/policies/vmess.html)。

### P2-7：完整 sing-box 配置的非 outbound 字段被无类型地复制到其他客户端

- 虚构输入：

  ```json
  {
    "dns":{"servers":[{"tag":"doh","address":"https://1.1.1.1/dns-query"}]},
    "route":{"rules":[]},
    "outbounds":[{"type":"trojan","tag":"t","server":"edge.example","server_port":443,"password":"p","tls":{"enabled":true}}]
  }
  ```

- 当前错误：`parseSingboxJson` 删除 `outbounds` 后把其余对象作为 `configOverrides`；`applyConfigOverrides` 除少数 blacklist 外直接复制。目标 Clash 得到 sing-box 形态的 `dns.servers`、`route` 等；Mihomo未知键可能被忽略，用户配置静默失效。Surge formatter则大量不输出这些字段。
- 正确预期：跨格式只导入已明确定义的可翻译字段；原生完整配置 override 仅允许同目标格式，或经过 format-specific translator。
- 证据：项目 [`subscriptionContentParser.js#L22-L49`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/parsers/subscription/subscriptionContentParser.js#L22-L49)、[`BaseConfigBuilder.js#L249-L281`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/builders/BaseConfigBuilder.js#L249-L281)。

---

## 5. 建议固化的 canonical contract

这不是实现方案，而是避免继续混用客户端 schema 所需的最小合同：

```text
Endpoint
  protocol + protocolVersion
  server (裸 hostname/IP，不含 [] 和端口) + port
  credentials (按协议 tagged union)
  tls
    enabled, serverName, certificateVerifyName?, insecure, alpn[]
    clientHelloFingerprint?
    certificatePin? { kind: certificate-sha256 | spki-sha256, value, encoding }
    ech? { enabled, config?: PEM-formatted ECH CONFIGS line(s), configPath?, queryServerName? }
    reality? { publicKey, shortId }
  transport
    kind: tcp | ws | http | http-obfs | grpc | httpupgrade | xhttp | ...
    # http = V2Ray HTTP/H2 body transport; http-obfs = one-shot TCP HTTP-header camouflage
    path(s), host(s), headers, serviceName, authority, target-specific extras
  capabilities
    udp: unspecified | allowed | forbidden
    tcpFastOpen?
  protocolOptions
    shadowsocksPlugin: raw SIP003 string + parsed lossless tokens
    shadowsocksr: protocol/protocolParam + obfs/obfsParam (never coerce to Shadowsocks)
    hysteria: canonical port intervals, hop Duration, bandwidth, auth/obfs, protocol mode
    hysteria2: direct/realm endpoint union, canonical port intervals, min/max hop Duration, numeric Mbps, obfs
    tuic: version/auth union, congestion, relay mode, zeroRtt, heartbeat Duration
    anytls: idle Durations, minIdleSession, metadata, reuse policy
  provenance
    sourceFormat + sourceVersion/dialect
```

Hysteria2 URI 的 `ech=` 是 raw Base64 ECHConfigList，只是输入 dialect；进入 canonical TLS 后应规范化为 sing-box-like `ECH CONFIGS` PEM line/line array。Mihomo serializer 再提取 PEM body 写入 `ech-opts.config`，不能把 raw Base64 与 PEM schema 混为同一种字段类型。

序列化规则：

- 支持且可无损：转换；
- 支持但需有文档依据的有损降级：显式报告；
- 客户端不支持或字段不足：拒绝该节点，不生成“看起来合法”的退化节点；
- 不识别的 URI 方言：拒绝，不能自动称为标准。

---

## 6. Windows / Go 可运行的真实 schema 验证

本机 `PATH` 未发现 `sing-box`/`mihomo`；遵守“不安装依赖”约束，本文没有下载或执行外部二进制。下面使用的是官方真实客户端命令及可直接运行的最小 fixture，而不是自制近似 schema。

### 6.1 sing-box：`check` + 版本匹配 JSON Schema

官方命令：

```powershell
& 'C:\Tools\sing-box.exe' check -c '.\candidate-singbox.json'
if ($LASTEXITCODE -ne 0) { throw 'sing-box schema/config check failed' }

# 自 1.14.0：生成与该二进制 build feature 完全匹配的 schema
& 'C:\Tools\sing-box.exe' schema -o '.\sing-box.schema.json'
if ($LASTEXITCODE -ne 0) { throw 'sing-box schema generation failed' }
```

来源：[configuration/check](https://sing-box.sagernet.org/configuration/)、[JSON Schema](https://sing-box.sagernet.org/configuration/schema/)、[`cmd_check.go`](https://github.com/SagerNet/sing-box/blob/v1.14.1/cmd/sing-box/cmd_check.go)。`check` 不只是 JSON parse，还构造 `box.New`，能发现 union discriminator、Duration、未知字段与初始化错误。

最小 AnyTLS fixture（不会在 `check` 时建立代理连接）：

```json
{
  "log": { "disabled": true },
  "outbounds": [
    {
      "type": "anytls",
      "tag": "candidate",
      "server": "127.0.0.1",
      "server_port": 443,
      "password": "x",
      "idle_session_check_interval": "30s",
      "idle_session_timeout": "30s",
      "min_idle_session": 0,
      "tls": {
        "enabled": true,
        "server_name": "example.com",
        "insecure": false
      }
    }
  ]
}
```

有价值的负例：把 Duration 改成数字 `30`；把 `transport.type` 改成 `h2`；把 SS `plugin_opts` 改成 object。目标版本 `v1.14.1` 应拒绝这些错型。验证其他协议时只替换 `outbounds[0]`，保持外围最小配置不变。

### 6.2 Mihomo：使用真正客户端 parser 的 `-t -f`

```powershell
& 'C:\Tools\mihomo-windows-amd64-v1.19.31.exe' -t -f '.\candidate-mihomo.yaml'
if ($LASTEXITCODE -ne 0) { throw 'mihomo config test failed' }
```

如配置引用相对路径，可再加 `-d <home-dir>`。CLI flag 由官方 [`main.go`](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/main.go)定义：`-t` 测试后退出，`-f` 指定配置。

最小 AnyTLS fixture：

```yaml
mode: rule
log-level: silent
proxies:
  - name: candidate
    type: anytls
    server: 127.0.0.1
    port: 443
    password: x
    udp: true
    idle-session-check-interval: 30
    idle-session-timeout: 30
    min-idle-session: 0
    sni: example.com
    skip-cert-verify: false
proxy-groups:
  - name: CHECK
    type: select
    proxies: [candidate]
rules:
  - MATCH,CHECK
```

验证其他协议时只替换 `proxies[0]` 及 group 中的同名引用。限制：Mihomo 的 [`common/structure`](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/common/structure/structure.go)会忽略未知 map key；因此 `mihomo -t` 是真实 parser/type/required-field 验证，但不是 strict unknown-field validator。例如 `"30s"` → int 会因 `strconv.ParseInt` 失败；而未知的 `zero-rtt` 可能通过但被忽略。能力审计仍需对照目标版本 outbound struct。

### 6.3 跨平台 Go wrapper（Windows 可直接 `go run`）

将下列内容保存为任意临时 `.go` 文件即可；它不重实现 schema，而是调用对应版本的真实客户端：

```go
package main

import (
    "flag"
    "fmt"
    "os"
    "os/exec"
)

func main() {
    client := flag.String("client", "", "sing-box or mihomo")
    bin := flag.String("bin", "", "path to client executable")
    config := flag.String("config", "", "path to config file")
    flag.Parse()

    if *bin == "" || *config == "" {
        fmt.Fprintln(os.Stderr, "-bin and -config are required")
        os.Exit(2)
    }

    var args []string
    switch *client {
    case "sing-box":
        args = []string{"check", "-c", *config}
    case "mihomo":
        args = []string{"-t", "-f", *config}
    default:
        fmt.Fprintln(os.Stderr, "-client must be sing-box or mihomo")
        os.Exit(2)
    }

    cmd := exec.Command(*bin, args...)
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    if err := cmd.Run(); err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
}
```

Windows 示例：

```powershell
go run .\validate-client-config.go `
  -client sing-box `
  -bin 'C:\Tools\sing-box.exe' `
  -config '.\candidate-singbox.json'

go run .\validate-client-config.go `
  -client mihomo `
  -bin 'C:\Tools\mihomo.exe' `
  -config '.\candidate-mihomo.yaml'
```

验证必须固定二进制版本；“当前网站 schema”不能替代用户实际安装版本。

### 6.4 Surge：没有可替代真实客户端的 Windows/Go strict validator

截至本文日期，Surge 没有公开的 Windows/Go 配置 schema validator，也没有可固定版本的公开 policy struct。不能用项目自己的 INI parser、也不能用“未知键未报错”证明字段受支持。自动回归只能对 serializer 做精确字符串/escaping 断言并引用当前官方手册；最终验收需在对应版本的 Surge for Mac/iOS 导入最小 profile。由于这是外部客户端行为，本文没有在本机伪造验证结果。

---

## 7. URI 标准状态与不确定性声明

| Scheme / 形态 | 可声称的范围 | 不得声称的内容 |
|---|---|---|
| `ss://` | Shadowsocks 项目的 SIP002；包括 Base64URL/明文 userinfo 与 `plugin=` escaping | 某客户端的 plugin map 结构不是 SIP002 |
| `ssr://` | 只能声明兼容某一历史 SSR QR-code dialect：整体 Base64URL，且 password/obfs-param/protocol-param/remarks/group 等字段有内层 Base64URL | 原项目已停更且没有当前维护的 canonical 标准；不是 SIP002，也不能把 SSR 节点无损降为 SS |
| `hysteria://` | Hysteria v1 官方归档 URI：host/port/upmbps/downmbps 必填；`auth` 在 query；`protocol` 缺省 `udp`，可选 `udp` / `wechat-video` / `faketcp`；`peer` 为 SNI，ALPN 缺省 `hysteria`，obfs 为 `xplus` + `obfsParam` | 与 Hysteria2 wire/URI 不兼容；不得把 userinfo 当 v1 auth，也不得派发给 v2 parser |
| `hysteria2://`, `hy2://`, `hysteria2+realm://`, `hysteria2+realm+http://`（以及非自包含的 `realm://` rendezvous URI） | Hysteria 2 官方 URI；直连 authority 可含 hopping port union；query 定义 `obfs`、`obfs-password`、`sni`、`insecure`、pin/ECH；Realm 另有 `auth`、可重复 `stun`、`lport` | `hysteria://` 不是 v2 alias；`alpn`、`mport`、`hop-interval` 不是当前官方 v2 URI query contract；Realm 不支持 port hopping，`realm://` 也不是完整节点凭据 |
| `anytls://` | AnyTLS 项目 URI；password/userinfo、host/port、`sni`、`insecure`、fragment | `alpn`、`fp`、`udp`、idle-session 参数只是实现扩展，不能宣称跨客户端标准 |
| `vless://` | Xray-core Discussion #716 的 canonical proposal；可作为 Xray 生态合同 | 不是 IETF/IANA 或已冻结的全生态标准；字段可随 proposal 演进 |
| `vmess://Base64(JSON)` | v2rayN 方言，项目代码可明确声明支持该 dialect；其中 `insecure` 等字段必须按该方言类型解析 | V2Fly 没有最终统一 VMess URI；不能笼统写“VMess 标准 URI” |
| `vmess://UUID@host:port?...` | Xray-core Discussion #716 的 authority-style VMessAEAD proposal；固定 AEAD/`alter_id=0`，`encryption` 缺省 `auto`，可承载 TLS/Reality 等 proposal 参数 | 仍是允许 breaking change 的 proposal，不是冻结标准；当前 `parseVmess` 只按 Base64(JSON) 解码，因此不能声称已支持该 dialect |
| `trojan://` | `trojan-gfw/trojan-url` 的最小 `password@host:port`，且原仓库明确“not finalized” | `sni/type/alpn/security/flow` 等扩展不是原始 finalized standard |
| `tuic://` | 只能写“本项目接受的 de facto dialect”，并逐项定义参数 | TUIC `SPEC.md` 只定义 wire protocol 0x05；官方 [issue #209](https://github.com/tuic-protocol/tuic/issues/209) 的标准化分享链接请求已关闭为 not planned，没有官方 share URI |

其他不确定性：

- Surge 手册是滚动更新，缺少 tag/commit 与公开 strict schema；本文只对 2026-09-20 当前手册和当前客户端版本作结论。
- “官方页面没有字段”与“运行时绝不接受未知字段”不是同一件事。Mihomo 明确会忽略很多未知 key；因此本文把“未在目标 struct/手册中定义”视为不得生成，而不是把 parser 宽容当作支持。
- Hysteria2 官方 Go client 的 URI parser不读取 `alpn`；协议内部使用 HTTP/3。项目当前接受 `?alpn=` 只能标为扩展。
- IPv6 的 canonical `server` 应保存裸 literal（例如 `2001:db8::1`），端口单列；每个 URI serializer 再加方括号。不要把 bracketed host 当内部值。
- AnyTLS `min_idle_session` 是保底维持的 idle session 数，不是最大值；当前 sing-box/Mihomo schema 都没有 `max_idle_session`，不得生成该键。

---

## 8. 主要 primary links

### 本项目调用路径

- [`ProxyParser.js`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/parsers/ProxyParser.js)
- [`subscriptionContentParser.js`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/parsers/subscription/subscriptionContentParser.js)
- [`convertYamlProxyToObject.js`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/parsers/convertYamlProxyToObject.js)
- [`convertSurgeProxyToObject.js`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/parsers/convertSurgeProxyToObject.js)
- [`ClashConfigBuilder.js`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/builders/ClashConfigBuilder.js)
- [`SingboxConfigBuilder.js`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/builders/SingboxConfigBuilder.js)
- [`SurgeConfigBuilder.js`](https://github.com/eicky/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/builders/SurgeConfigBuilder.js)

### 客户端 schema

- sing-box：[outbound index](https://sing-box.sagernet.org/configuration/outbound/)、[V2Ray transport](https://sing-box.sagernet.org/configuration/shared/v2ray-transport/)、[TLS](https://sing-box.sagernet.org/configuration/shared/tls/)、[`option/` v1.14.1](https://github.com/SagerNet/sing-box/tree/v1.14.1/option)
- Mihomo：[proxy docs](https://wiki.metacubex.one/en/config/proxies/)、[transport](https://wiki.metacubex.one/en/config/proxies/transport/)、[TLS](https://wiki.metacubex.one/en/config/proxies/tls/)、[`adapter/outbound` v1.19.31](https://github.com/MetaCubeX/mihomo/tree/v1.19.31/adapter/outbound)
- Surge：[policy overview](https://manual.nssurge.com/policies/overview.html)、[TLS](https://manual.nssurge.com/policies/tls.html)、[UDP](https://manual.nssurge.com/policies/udp.html)、[common parameters](https://manual.nssurge.com/policies/parameters.html)

### 协议/分享格式

- Shadowsocks [SIP002](https://shadowsocks.org/doc/sip002.html) 与官方 legacy [`configs.md`](https://github.com/shadowsocks/shadowsocks-org/blob/main/docs/doc/configs.md)
- ShadowsocksR 历史 [SSR QR-code scheme 镜像](https://github-wiki-see.page/m/HMBSbige/shadowsocks-rss/wiki/SSR-QRcode-scheme)（原项目已停更，非当前维护标准）
- Hysteria v1 [归档 URI Scheme](https://v1.hysteria.network/docs/uri-scheme/)
- Hysteria 2 [pinned URI Scheme](https://github.com/HyNetworks/hysteria-website/blob/d5c6fa441ab31b7726205ae4451f828cebe5263d/docs/docs/developers/URI-Scheme.md) 与 [pinned Port Hopping](https://github.com/HyNetworks/hysteria-website/blob/d5c6fa441ab31b7726205ae4451f828cebe5263d/docs/docs/advanced/Port-Hopping.md)
- AnyTLS [`docs/uri_scheme.md`](https://github.com/anytls/anytls-go/blob/fd6167acd6d73b9fa3e607659951847fbc9e6c50/docs/uri_scheme.md)
- TUIC [`SPEC.md`](https://github.com/tuic-protocol/tuic/blob/master/SPEC.md) 与[不制定标准分享链接的 maintainer 结论](https://github.com/tuic-protocol/tuic/issues/209#issuecomment-1636147733)
- VLESS [Xray-core Discussion #716](https://github.com/XTLS/Xray-core/discussions/716)
- VMess [v2rayN share-link dialect](https://github.com/2dust/v2rayN/wiki/Description-of-VMess-share-link)、Xray-core [authority-style VMessAEAD proposal #716](https://github.com/XTLS/Xray-core/discussions/716) 与 V2Fly [closed proposal #26](https://github.com/v2fly/v2fly-github-io/issues/26)
- Trojan [`trojan-url`](https://github.com/trojan-gfw/trojan-url)
