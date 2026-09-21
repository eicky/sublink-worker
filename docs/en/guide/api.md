# HTTP Endpoints

Conversion endpoints use `GET`. Pass the source through the URL-encoded `config` query parameter.

## Conversion endpoints

| Path | Output |
|---|---|
| `/clash` | Mihomo / Clash.Meta YAML |
| `/singbox` | sing-box JSON |
| `/surge` | Surge INI |
| `/xray` | Base64 share-link list, not Xray JSON |
| `/subconverter` | Rule configuration in a subconverter-compatible form |

Example with fictional data:

```sh
curl --get 'http://localhost:8787/singbox' \
  --data-urlencode 'config=vless://00000000-0000-4000-8000-000000000001@node.example:443?security=tls#Example'
```

## Common parameters

| Parameter | Meaning |
|---|---|
| `config` | Required source URI, subscription content, or remote URL |
| `ua` | User-Agent used for remote subscription requests |
| `selectedRules` | Preset name or JSON array |
| `customRules` | JSON array of custom rules |
| `group_by_country` | Enable country or region groups |
| `include_auto_select` | Set to `false` to omit the automatic selection group |
| `skip_cert_verify` | `/clash` and `/singbox` only; defaults to `true`, skipping proxy TLS certificate and pin verification, not REALITY. Set to `false` to preserve the subscription's verification policy. See [scope](/en/protocol-support#certificate-verification-policy) |
| `configId` | Use a saved, format-compatible base configuration |
| `singbox_version` | Target sing-box version; `sb_version` and `sb_ver` are aliases |
| `enable_clash_ui` | Enable external UI configuration where supported |
| `external_controller` | Override the external controller address |
| `external_ui_download_url` | Override the UI download URL |

Use explicit boolean strings. Unsupported target combinations return `400` instead of dropping critical fields.

## Short links

Create one with:

```text
GET /shorten-v2?url=<full-conversion-url>&shortCode=<optional-code>
```

The target-specific short paths are `/c/:code`, `/b/:code`, `/s/:code`, and `/x/:code`. Short links require an available KV adapter.

## Saved base configurations

```http
POST /config
Content-Type: application/json

{
  "type": "clash",
  "content": "..."
}
```

Use the returned `configId` only with a matching target format. Cross-format input retains normalized proxies and groups, but does not inject client-specific DNS, routing, or listener fields into another client.

## Error handling

Malformed recognized protocols, invalid parameters, and unsupported target mappings return clean errors without reflecting the full credential-bearing URI.
