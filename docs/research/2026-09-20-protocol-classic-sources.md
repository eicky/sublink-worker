# Shadowsocks 与 VMess 经典分享格式来源核对

- 调研日期：2026-09-20
- 范围：`ss://`（SIP002/SIP003/SIP022 与旧二维码格式）、Xray VMessAEAD authority-style proposal 及 v2rayN 风格 `vmess://Base64(JSON)`
- 目标：只按规范或官方实现确定解析规则；把规范、客户端约定与本项目兼容行为分开

## 结论

1. Shadowsocks 的 SIP002 是正式 URI 约定；现代格式、旧整段 Base64 格式和 AEAD-2022 明文 userinfo 是三条不同分支，不能用同一条“先 Base64 再按 `:`/`@` 全量 split”的逻辑处理。
2. SIP003 的插件名和选项名属于协议输入，parser 不应提前改成 Clash 字段；目标客户端适配应由 builder 完成。
3. V2Fly VMess 线协议本身没有已冻结的统一分享 URL。常见的 `vmess://Base64(JSON)` 是 v2rayN 客户端约定；`vmess://UUID@host:port?...` 来自 Xray-core Discussion #716 的 VMessAEAD/VLESS 分享链接提案。两者都必须标明来源，不能笼统宣称为 V2Fly 统一标准。
4. 对本项目不能无损表示的 KCP、QUIC、`vcn` 等值应拒绝，而不是返回一个缺字段但看似成功的 outbound；可保留的 `pcs` 则进入内部 TLS 证书 SHA 字段，由目标 builder 决定支持或明确拒绝。

## 一、Shadowsocks

### Primary sources

以下 Shadowsocks 文档固定在 `shadowsocks-org` commit [`34598d65054dad975d330ff9d7317b0d41cf1efd`](https://github.com/shadowsocks/shadowsocks-org/commit/34598d65054dad975d330ff9d7317b0d41cf1efd)（2026-07-12）：

- [SIP002 URI Scheme](https://github.com/shadowsocks/shadowsocks-org/blob/34598d65054dad975d330ff9d7317b0d41cf1efd/docs/doc/sip002.md)
- [SIP003: A simplified plugin design](https://github.com/shadowsocks/shadowsocks-org/blob/34598d65054dad975d330ff9d7317b0d41cf1efd/docs/doc/sip003.md)
- [SIP022: Shadowsocks 2022 Edition](https://github.com/shadowsocks/shadowsocks-org/blob/34598d65054dad975d330ff9d7317b0d41cf1efd/docs/doc/sip022.md)
- [Config Format：旧 URI/二维码格式](https://github.com/shadowsocks/shadowsocks-org/blob/34598d65054dad975d330ff9d7317b0d41cf1efd/docs/doc/configs.md)

实现交叉验证：

- `shadowsocks-rust` commit [`157cefa96d44de848ff218119dbec2047826c1bb`](https://github.com/shadowsocks/shadowsocks-rust/commit/157cefa96d44de848ff218119dbec2047826c1bb) 的 [`ServerConfig::from_url` / `to_url`](https://github.com/shadowsocks/shadowsocks-rust/blob/157cefa96d44de848ff218119dbec2047826c1bb/crates/shadowsocks/src/config.rs)
- [RFC 3986 URI authority/userinfo/IP-literal](https://datatracker.ietf.org/doc/html/rfc3986#section-3.2)
- [RFC 4648 Base64URL](https://datatracker.ietf.org/doc/html/rfc4648#section-5)

### SIP002 规则

规范结构为：

```text
ss://userinfo@hostname:port[/][?plugin][#tag]
```

- Stream 和 SIP004 AEAD：`userinfo` 推荐使用 `Base64URL(UTF-8(method ":" password))`，但当前 SIP002 也允许不做 Base64URL；明文形式中的 method/password 必须做百分号编码。
- SIP022 AEAD-2022：`userinfo` **不得**再包 Base64URL，必须使用百分号编码的 `method:password`。例如 Base64 PSK 中的 `+`、`/`、`=` 分别需要 URI 编码。
- 分隔符解析顺序：先找 userinfo 中第一个未编码的 `:` 作为 method/password 边界，再解百分号编码；密码中的冒号必须保留。authority 的服务器边界应使用最后一个 `@`，旧格式密码本身可以含 `@`。
- `userinfo` 的 Base64 解码结果是 UTF-8，不是 Latin-1/binary string。
- SIP002 示例使用无 padding 的 Base64URL，但文档没有把“必须去 padding”写成独立强制条款；兼容解析应同时接受有/无 `=` padding。旧整段 Base64 文档则明确写为 `WITHOUT-PADDING`。
- IPv6 URI host 按 RFC 3986 必须使用方括号，例如 `[2001:db8::1]:8388`。
- `shadowsocks-rust` 对省略端口的输入会回退到 `8388`，但 SIP002 grammar 本身把 `:port` 列为必需项；本项目 parser 选择要求显式端口，不把实现层兼容默认写成规范规则。
- `tag` 是 URI fragment，按百分号编码处理；`+` 在 fragment 中不是空格替代符。

### SIP003 插件

- SIP002 用 `?plugin=<URL-encoded plugin string>` 携带插件，并写明存在 plugin 时 authority 后 **should** 带 `/`（不是 MUST）；兼容 parser 可同时接受省略该 slash 的既有链接。
- 插件字符串由插件名和分号分隔选项组成，例如 `simple-obfs;obfs=http;obfs-host=example.com`。
- SIP002/SIP003 要求插件数据中的 `:`、`;`、`=`、`\` 用反斜杠转义。解析器必须按“未转义分号/等号”切分，不能直接 `split(';')`。
- 官方实现和示例存在 `v2ray-plugin;server;tls` 这样的无值 flag；兼容解析保留为布尔 `true`。
- SIP003 没有规定把 `simple-obfs` 政名为 Clash 的 `obfs`，也没有规定把 `obfs-host` 政名为 `host`。这些是目标客户端适配，属于 builder，不属于 URI parser。
- SIP002 说明未知 query 参数可忽略。

### SIP022 密钥

- 必需方法：`2022-blake3-aes-128-gcm`、`2022-blake3-aes-256-gcm`。
- 可选标准方法：`2022-blake3-chacha20-poly1305`、`2022-blake3-chacha12-poly1305`、`2022-blake3-chacha8-poly1305`。
- PSK 是直接提供的 Base64 key，不再使用旧 `EVP_BytesToKey` 密码派生。
- AES-128 的 Base64 解码结果必须为 16 字节；AES-256 为 32 字节。ChaCha 系列由官方实现的 cipher key size 确认为 32 字节。
- AEAD-2022 identity key 列表以冒号连接时，每一段都必须满足对应 key size；解析 userinfo 时不能因冒号而截断密码。

### 旧整段 Base64 兼容格式

官方 Config Format 仍记录：

```text
ss://BASE64-WITHOUT-PADDING(method:password@hostname:port)#TAG
```

该格式不是 SIP002 userinfo Base64：Base64 包住的是整个 `method:password@host:port`。官方示例密码包含 `/!@#:`，因此解码后必须：

1. 用最后一个 `@` 找服务器；
2. 用第一个 `:` 找 method；
3. 保留密码中剩余的 `@`、`#`、`:`；
4. 再按 IPv6 bracket/port 规则解析服务器。

`shadowsocks-rust` 的官方 parser 也保留了这一递归兼容分支。AEAD-2022 不应使用旧整段 Base64 格式。

## 二、VMess

### VMess 分享 URL 的标准地位

V2Fly 官方指南明确说明：[V2Ray 不像 Shadowsocks 那样有统一规定的 URL 格式，各图形客户端的分享链接/二维码不一定通用](https://guide.v2fly.org/en_US/)。V2Fly 的 [VMess 协议文档](https://github.com/v2fly/v2fly-github-io/blob/094c084eef448fc573f2228acc847911ca78ae11/docs/developer/protocols/vmess.md) 描述线协议、UUID 和载荷安全方式，但不定义分享 URL 字段。

本项目明确支持两种不同来源的 dialect：

1. Xray-core [Discussion #716](https://github.com/XTLS/Xray-core/discussions/716) 的 authority-style VMessAEAD/VLESS 分享链接**提案**；页面自身说明格式会随协议演进而发生 breaking change，不是已冻结的 V2Fly 通用标准。
2. v2rayN 的 `vmess://Base64(UTF-8 JSON)` 客户端约定。

### Xray VMessAEAD authority-style proposal

提案结构为：

```text
vmess://UUID@remote-host:remote-port?<protocol><transport><tls>#description
```

- 只表示 VMess AEAD，固定 `alter_id=0`；`aid`/`alterId` 不属于该格式。
- `encryption` 允许 `auto`、`aes-128-gcm`、`chacha20-poly1305`、`none`，省略时为 `auto`；空值和 legacy-only `zero` 不合法。
- `security` 允许 `none`、`tls`、`reality`，省略时为 `none`。TLS/REALITY 的 `sni` 省略时回退到远端 host，不能回退到 transport 的 HTTP `host`。
- `fp` 省略时按提案使用 `chrome`；该格式没有 `allowInsecure`/`insecure` 字段。
- `type` 的正式值为 `tcp`、`kcp`、`ws`、`http`、`grpc`、`httpupgrade`、`xhttp`。v2rayN 当前 resolver 对省略值兼容为 raw/TCP，本项目保留该兼容默认，但不把它描述为提案正文的明确默认。
- transport 字段是上下文相关的：WS/HTTPUpgrade 使用 `host/path`；gRPC 使用 `serviceName/mode/authority`，mode 只接受 `gun`、`multi`、`guna`；XHTTP 使用 `host/path/mode/extra`；KCP 使用 `mtu/tti`。字段出现在错误 transport 时应拒绝，不能静默丢弃。
- 当前 canonical 模型无法表示 KCP 参数和 FinalMask，因此 `kcp`/`fm` 明确拒绝。非空 `ech` 经共享 Base64 校验与 PEM 规范化进入内部 `tls.ech`，提案允许的空值表示未配置 ECH；REALITY `pqv/spx` 和非空 `vcn` 当前没有无损内部字段，必须拒绝。
- 单个 `pcs` 十六进制 SHA-256 pin（允许 OpenSSL 冒号格式及周围空白）可规范化为内部 `tls.certificate_sha256`；提案/Xray 接受多 pin，但当前内部模型只有单值，因此多值输入拒绝。
- query key、固定值大小写敏感，同名 key 不得重复；未定义 query 不按 legacy JSON 字段猜测。

### v2rayN primary sources

固定源码 commit：[`28139853a8087d81e1ac7ffaf7013b937958f5d2`](https://github.com/2dust/v2rayN/commit/28139853a8087d81e1ac7ffaf7013b937958f5d2)（2026-09-20）：

- [VMess 分享链接 wiki revision `1e98189`](https://github.com/2dust/v2rayN/wiki/Description-of-VMess-share-link/1e98189ad592b13a3a13bd4e5e7e757bee952a65)
- [`VmessFmt.ResolveVmess` / `ResolveStdVmess` / `ToUri`](https://github.com/2dust/v2rayN/blob/28139853a8087d81e1ac7ffaf7013b937958f5d2/v2rayN/ServiceLib/Handler/Fmt/VmessFmt.cs)
- [`BaseFmt.ResolveUriQuery`](https://github.com/2dust/v2rayN/blob/28139853a8087d81e1ac7ffaf7013b937958f5d2/v2rayN/ServiceLib/Handler/Fmt/BaseFmt.cs)
- [`VmessQRCode` DTO](https://github.com/2dust/v2rayN/blob/28139853a8087d81e1ac7ffaf7013b937958f5d2/v2rayN/ServiceLib/Models/Dto/VmessQRCode.cs)
- [`Utils.Base64Decode`](https://github.com/2dust/v2rayN/blob/28139853a8087d81e1ac7ffaf7013b937958f5d2/v2rayN/ServiceLib/Common/Utils.cs)
- [`JsonUtils.Deserialize` options](https://github.com/2dust/v2rayN/blob/28139853a8087d81e1ac7ffaf7013b937958f5d2/v2rayN/ServiceLib/Common/JsonUtils.cs)
- [`Global` transport/default constants](https://github.com/2dust/v2rayN/blob/28139853a8087d81e1ac7ffaf7013b937958f5d2/v2rayN/ServiceLib/Global.cs)
- Xray-core commit [`47cfe99`](https://github.com/XTLS/Xray-core/commit/47cfe9994a6b39b1f673ba35e62b091bcce15a71) 的 [`pinnedPeerCertSha256` / `verifyPeerCertByName` parser](https://github.com/XTLS/Xray-core/blob/47cfe9994a6b39b1f673ba35e62b091bcce15a71/infra/conf/transport_security.go#L361-L389)

VMess 配置约束交叉验证：V2Fly commit [`094c084eef448fc573f2228acc847911ca78ae11`](https://github.com/v2fly/v2fly-github-io/commit/094c084eef448fc573f2228acc847911ca78ae11) 的 [VMess 配置文档](https://github.com/v2fly/v2fly-github-io/blob/094c084eef448fc573f2228acc847911ca78ae11/docs/config/protocols/vmess.md)。

### JSON 外壳与字段类型

v2rayN 文档格式是：

```text
vmess://Base64(UTF-8 JSON object)
```

- v2rayN `Base64Decode` 同时接受标准 Base64 和 Base64URL，移除空白，补齐缺失 padding，并按 UTF-8 还原 JSON。
- v2rayN 的 JSON 反序列化配置对 property name 大小写不敏感；兼容解析也应如此，并拒绝大小写不同但语义重复的字段。
- DTO 中 `v`、`port`、`aid` 是 `int`，允许 JSON number 或十进制 JSON string；不能用 `parseInt` 接受 `443junk` 之类前缀数字。
- `ps/add/id/scy/net/type/host/path/tls/sni/alpn/fp/insecure/vcn/pcs` 是 string。
- `id` 是 UUID；V2Fly 文档要求有效 UUID。
- `alterId` 默认 `0`，最大 `65535`；`0` 使用 VMessAEAD。
- `security/scy` 默认 `auto`；V2Fly 文档列出的值是 `auto`、`aes-128-gcm`、`chacha20-poly1305`、`none`、`zero`。
- `ps` 是可空备注，不是连接必需字段；本项目为无备注节点用 `server:port` 派生内部 tag，避免有效节点被 builder 丢弃。

### TLS 字段

- `tls` 的分享值为 `tls`；空值/`none` 表示未启用。其他模式不能假装普通 TLS 成功。
- `sni` 映射 TLS server name；不能拿它代替 WebSocket/H2 的 HTTP Host。旧 JSON 的缺省 SNI 需匹配 [v2rayN `FillOutboundTls`](https://github.com/2dust/v2rayN/blob/28139853a8087d81e1ac7ffaf7013b937958f5d2/v2rayN/ServiceLib/Services/CoreConfig/Singbox/SingboxOutboundService.cs)：TCP/WS/HTTPUpgrade/XHTTP/gRPC 可从 transport Host/authority 列表第一项回退。这与 authority-style proposal 的 remote-host 缺省规则不同，两个 dialect 不能混用。
- `alpn` 是逗号分隔列表。
- `fp` 是 TLS fingerprint，映射到内部 `tls.utls`。
- `insecure` 的 v2rayN 有效值为 string `0` 或 `1`；DTO 的空缺省字符串按 false 处理。`"0"` 不能因 JavaScript truthy 规则变成 `true`。
- `vcn`（证书名称验证）和 `pcs`（证书 SHA）是当前 v2rayN 字段。单个 `pcs` 必须是 32 字节 SHA-256 的 64 位十六进制指纹（可带 OpenSSL 风格冒号），规范化后保留为内部 `tls.certificate_sha256`；当前内部字段不能无损携带多个 pin，因此多值输入应拒绝。不支持该语义的目标 builder 再明确拒绝。`vcn` 与 SNI 不等价，当前内部模型无法无损表示，因此 parser 拒绝非空 `vcn`。

### Transport 字段

v2rayN 用 `net/type/host/path` 复用表示不同 transport。内部应先规范化，再由目标 builder 转换：

| v2rayN JSON | 内部 transport | 说明 |
|---|---|---|
| `net=tcp`, `type=none` 或缺省 | 无 transport | 普通 TCP/raw |
| `net=tcp,type=http` | `type=http-obfs` | TCP HTTP camouflage；不能与 H2 混为 `http` |
| `net=ws` | `type=ws` | `host` 是 HTTP Host，`path` 是 WS path |
| `net=h2`；兼容 `net=http` | `type=http` | 规范到 sing-box-like HTTP transport；`host` 为列表 |
| `net=grpc` | `type=grpc` | `path` → `service_name`，`host` → `authority`，`type` 可携带 `gun`/`multi` mode |
| `net=httpupgrade` | `type=httpupgrade` | 当前 v2rayN 源码支持 |
| `net=xhttp` | `type=xhttp` | `type` 是 `auto`、`packet-up`、`stream-up`、`stream-one` mode；`host/path` 保留 |
| `net=kcp` / `net=quic` | 拒绝 | v2rayN wiki 有定义，但当前项目 sing-box-like 模型/目标 builder 不能无损表示其 header/seed/security/key 语义 |

v2rayN 当前源码也会读取 authority-style `vmess://uuid@host:port?...`，其 query resolver 与 Xray 提案一致。本项目按 authority 中是否存在 userinfo `@` 区分该分支与 Base64 JSON，避免把两种 dialect 混为同一套字段。

JSON payload 外追加 `#fragment` 覆盖 `ps` 是本项目保留的兼容行为，不属于 v2rayN JSON 文档格式。

## 三、实现与 builder 边界

- Parser 输出保留协议语义；Clash/Mihomo 命名转换放在 builder：例如 `simple-obfs`/`obfs-host` 到 `obfs`/`host`。
- Sing-box Shadowsocks plugin 需要把 option object 序列化回 SIP003 escaped string；不能直接输出 object。
- `http`（H2）与 `http-obfs`（TCP HTTP camouflage）必须保持不同内部类型。
- gRPC `authority`、XHTTP mode、KCP/QUIC、VMess `vcn` 以及 `pcs` 对应的证书 SHA 在某些目标格式不可表示时，builder 或 parser 应明确报错；不能静默降级。
- VMess JSON 的 `headers`、外部 fragment、`net=http` 等不是当前 v2rayN DTO 的规范字段/值；若保留，只能标为既有兼容扩展，不能写成 VMess 协议标准。
