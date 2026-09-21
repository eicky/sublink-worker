# HTTP 接口

所有转换接口都使用 `GET`，核心输入通过 `config` 查询参数传递。分享链接、Base64 内容或远程订阅 URL 必须正确 URL 编码。

## 转换接口

| 路径 | Content-Type | 说明 |
|---|---|---|
| `/clash` | `text/yaml` | 生成 Mihomo / Clash.Meta 配置 |
| `/singbox` | `application/json` | 生成 sing-box 配置 |
| `/surge` | 文本 | 生成 Surge 配置 |
| `/xray` | 文本 | 生成 Base64 分享链接列表，不是 Xray JSON |
| `/subconverter` | 文本 | 生成 subconverter 风格的规则配置 |

### 最小请求

```sh
curl --get 'http://localhost:8787/singbox' \
  --data-urlencode 'config=vless://00000000-0000-4000-8000-000000000001@node.example:443?security=tls#Example'
```

示例使用虚构节点。

## 常用查询参数

| 参数 | 接口 | 说明 |
|---|---|---|
| `config` | 四个转换接口 | 必填；分享链接、订阅内容或远程订阅 URL |
| `ua` | 四个转换接口 | 获取远程订阅时使用的 User-Agent；缺省取请求头或项目默认值 |
| `selectedRules` | clash / singbox / surge / subconverter | 预设名或 JSON 数组 |
| `customRules` | clash / singbox / surge / subconverter | JSON 数组格式的自定义规则 |
| `group_by_country` | clash / singbox / surge / subconverter | `true` 时按国家或地区分组 |
| `include_auto_select` | clash / singbox / surge / subconverter | 设为 `false` 时不生成自动选择组 |
| `skip_cert_verify` | clash / singbox | 默认 `true`，跳过代理 TLS 证书及指纹校验，不影响 REALITY；设为 `false` 保留原订阅的校验策略。详见[作用范围](/protocol-support#代理服务器证书校验策略) |
| `configId` | clash / singbox / surge | 使用已保存且格式匹配的基础配置 |
| `singbox_version` | singbox | 目标 sing-box 版本；也接受 `sb_version`、`sb_ver` 别名 |
| `enable_clash_ui` | clash / singbox | 启用对应的外部 UI 配置 |
| `external_controller` | clash / singbox | 自定义 external controller |
| `external_ui_download_url` | clash / singbox | 自定义 UI 下载地址 |

布尔值使用明确的字符串形式；不要依赖任意非空字符串等同于 `true`。

## 目标版本

`/singbox` 会从显式参数或客户端 User-Agent 推断目标配置版本。涉及 AnyTLS、Hysteria2 Gecko、随机 hopping 上界等较新字段时，应显式传入兼容版本，例如：

```text
singbox_version=1.14
```

不兼容的组合返回 `400`，不会静默删除关键字段。

## 订阅流量信息

如果远程订阅响应含 `subscription-userinfo`，转换接口会尽可能把该响应头传递给客户端。

## 短链

### 创建

```text
GET /shorten-v2?url=<完整转换URL>&shortCode=<可选自定义代码>
```

该功能需要可用 KV。返回短码后，根据目标格式使用：

| 路径 | 目标 |
|---|---|
| `/c/:code` | Mihomo |
| `/b/:code` | sing-box |
| `/s/:code` | Surge |
| `/x/:code` | Base64 URI 订阅 |

### 解析

```text
GET /resolve?url=<短链URL>
```

## 保存基础配置

```http
POST /config
Content-Type: application/json

{
  "type": "clash",
  "content": "..."
}
```

返回的 `configId` 可用于格式匹配的转换接口。跨格式输入只保留可规范化的代理和代理组，不会把某个客户端专属的 DNS、路由或 listener 字段原样注入另一个客户端。

## 错误响应

- 缺少必填参数：`400`
- 已识别但格式错误的协议链接：`400`
- 目标客户端无法表达该组合：`400`，或在 Surge 输出中生成不参与选择组的 `Unsupported` 注释
- 需要 KV 但没有可用存储：依赖缺失错误

错误信息不会回显完整的含密码分享链接。
