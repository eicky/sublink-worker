# ShadowsocksR `ssr://` URI 格式来源

- 调研日期：2026-09-20
- 结论：ShadowsocksR 使用独立的 `ssr://` 双层 Base64URL 格式，不是 Shadowsocks SIP002 的 `ss://` URI。

## 规范结论

归档的原 SSR QR-code 文档给出的格式是：

```text
ssr://Base64URL(
  host:port:protocol:method:obfs:Base64URL(password)
  /?obfsparam=Base64URL(obfs_param)
  &protoparam=Base64URL(protocol_param)
  &remarks=Base64URL(remarks)
  &group=Base64URL(group)
  &udpport=0
  &uot=0
)
```

编码规则：

1. 文本先按 UTF-8 编码，再做 URL-safe Base64。
2. 规范生成形式去掉末尾 `=` padding。
3. 密码先单独编码；`obfsparam`、`protoparam`、`remarks`、`group` 的值也分别单独编码；最后再编码整个内部载荷。
4. 六个核心字段的顺序固定；`/?` 及查询参数可省略。
5. `udpport`、`uot` 是 C# 客户端扩展，不是核心 SSR 出站字段。

原 wiki 已从 `breakwa11/shadowsocks-rss` 删除。`shadowsocksrr/electron-ssr` 的官方参考列表同时保留了[已删除的原链接和备份链接](https://github.com/shadowsocksrr/electron-ssr/blob/28cc5d27bd747854438878d920e45ff36ca4a1b3/README.md#L122-L127)；本次采用其指向的 [`shadowsocksr-backup` 归档页](https://github.com/shadowsocksr-backup/shadowsocks-rss/wiki/SSR-QRcode-scheme)，调研时 wiki Git HEAD 为 `415486e9f462f8977f1a6d2a86eac30a6b289d35`。

## 源代码交叉验证

| 行为 | Primary source |
|---|---|
| C# 客户端解析 `ssr://`，按 `server:port:protocol:method:obfs:password` 取字段，并读取 `protoparam`、`obfsparam`、`remarks`、`group`、`uot`、`udpport` | [`ServerFromSSR`](https://github.com/shadowsocksrr/shadowsocksr-csharp/blob/e14f56f36cac527ae0398c0b1e84593732f7a3e2/shadowsocks-csharp/Model/Server.cs#L337-L420) |
| C# 客户端按相同顺序生成内部载荷，分别编码密码和查询值，最后编码整个载荷并只使用 `ssr://` | [`GetSSRLinkForServer`](https://github.com/shadowsocksrr/shadowsocksr-csharp/blob/e14f56f36cac527ae0398c0b1e84593732f7a3e2/shadowsocks-csharp/Model/Server.cs#L454-L479) |
| URL-safe Base64 使用 UTF-8、`+`→`-`、`/`→`_`；生成默认去 padding，解码会补齐 padding | [`Util/Base64.cs`](https://github.com/shadowsocksrr/shadowsocksr-csharp/blob/e14f56f36cac527ae0398c0b1e84593732f7a3e2/shadowsocks-csharp/Util/Base64.cs#L13-L47) |
| Python SSR 项目同样生成 `server:port:protocol:method:obfs:Base64URL(password)`，可加 `protoparam`，外层仍为 `ssr://Base64URL(...)` | [`mujson_mgr.py::ssrlink`](https://github.com/shadowsocksrr/shadowsocksr/blob/fd723a92c488d202b407323f0512987346944136/mujson_mgr.py#L66-L82) |
| 原项目在生成和解析时删除 protocol/obfs 名称中的 `_compatible`；空 protocol/obfs 在 C# 客户端分别回退到 `origin`/`plain` | [C# parser L384-L391](https://github.com/shadowsocksrr/shadowsocksr-csharp/blob/e14f56f36cac527ae0398c0b1e84593732f7a3e2/shadowsocks-csharp/Model/Server.cs#L384-L391)、[Python generator L66-L81](https://github.com/shadowsocksrr/shadowsocksr/blob/fd723a92c488d202b407323f0512987346944136/mujson_mgr.py#L66-L81) |

### Padding

规范要求生成无 padding 的 Base64URL。C# 解码器会在长度不足四的倍数时补 `=`，且没有启用“拒绝已有 `=`”的检查，因此兼容合法的 padded/unpadded 嵌套值；外层解析正则只捕获 URL-safe 字符并非末尾锚定，也会忽略外层尾随 padding。实现据此接受两种输入，但不把 padded 形式描述为规范输出。

### IPv6

归档格式页没有单独规定 IPv6 括号。C# 生成器直接拼接 `server + ":" + port`，解析器的第一个捕获组是贪婪的 `(.+)`，所以原客户端实际能解析未加括号的 IPv6。当前实现从右侧拆出五个非 host 字段，因此保留这一行为；同时接受 `[IPv6]` 并在内部去掉括号。后者是输入兼容能力，不代表原生成器会输出括号。

### Scheme 边界

三个 SSR primary sources 都只定义 `ssr://`。C# 匹配使用 `RegexOptions.IgnoreCase`，所以大小写不敏感；没有来源支持 `shadowsocksr://` 别名。当前实现只接受大小写不敏感的 `ssr://`。

Shadowsocks 官方 SIP002 则定义 `ss://userinfo@hostname:port`，其中 userinfo 通常是 `Base64URL(method:password)`；见 [`shadowsocks/shadowsocks-org` 的 SIP002 URI Scheme](https://github.com/shadowsocks/shadowsocks-org/wiki/SIP002-URI-Scheme)。它没有 SSR 的 protocol、obfs、嵌套查询值或整体第二层编码，不能复用为 SSR 解析规则。

## 本项目映射与边界

`parseShadowsocksR` 输出：

```js
{
    type: 'shadowsocksr',
    tag,
    server,
    server_port,
    method,
    password,
    protocol,
    protocol_param,
    obfs,
    obfs_param
}
```

- `remarks` 映射为 `tag`；缺失时使用 `<server>:<port>`，IPv6 使用 `[server]:port`。
- `group` 是订阅分组元数据。解析器会按规范解码并校验它，但不把它作为客户端出站字段泄露。
- C# `ParseParam` 遇到重复 key 时以后值覆盖前值；本实现对已映射参数同样取最后一个值。
- `uot`、`udpport` 是历史 C# 扩展，不映射到上述协议对象。
- 端口必须是十进制整数 `1..65535`。C# 源码使用 `ushort.Parse`；本项目额外拒绝符号、空白、浮点数和尾随字符，避免 `parseInt` 式截断。
- 已识别的 `ssr://` 中，Base64URL、UTF-8、核心字段或已映射查询值无效时抛出 `InvalidPayloadError`；非 SSR scheme 返回 `null`。
- 此解析器只建立规范化的内部 SSR 对象；各输出客户端是否仍支持 SSR，由对应 builder 明确接受或拒绝，不能把 SSR 字段伪装成 Shadowsocks 字段。
