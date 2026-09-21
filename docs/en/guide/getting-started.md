# Overview

Sublink Worker is a self-hosted proxy subscription converter and manager. It parses each source into a normalized representation and then applies target-specific conversion rules, rather than copying similar-looking but incompatible fields between clients.

## Inputs

- Shadowsocks, ShadowsocksR, VMess, VLESS, Trojan
- Hysteria v1, Hysteria2 / HY2, TUIC, AnyTLS
- Base64 and Base64URL subscriptions
- Remote HTTP(S) subscriptions
- Mihomo YAML, sing-box JSON, and Surge INI

## Outputs

| Endpoint | Output |
|---|---|
| `/clash` | Mihomo / Clash.Meta YAML |
| `/singbox` | sing-box JSON |
| `/surge` | Surge INI |
| `/xray` | Base64-encoded share-link list, not Xray JSON |

Successful parsing does not mean every client can express the same node. See [protocol support](/en/protocol-support) for target-specific limits.

## Run from source

```sh
git clone https://github.com/eicky/sublink-worker.git
cd sublink-worker
npm ci
npm run dev:node
```

Open `http://localhost:8787`. For the local Cloudflare runtime, use `npm run dev` instead.

## First conversion

The following credentials and hostname are intentionally fictional:

```sh
curl --get 'http://localhost:8787/clash' \
  --data-urlencode 'config=trojan://example-password@node.example:443#Example'
```

Change the path to `/singbox` or `/surge` for another target format.

## Choose a runtime

| Scenario | Recommended option |
|---|---|
| Low-maintenance serverless deployment | Cloudflare Workers |
| Existing Vercel project | Vercel |
| Server with Redis | Docker Compose |
| Desktop or lightweight server | Standalone release package |
| Development and customization | Node.js source checkout |

Continue with the [deployment guide](/en/guide/deployment).

## Privacy model

The GitHub Pages site is static and never processes subscriptions. Subscription content is sent to the converter instance you access. During remote conversion, that instance fetches the subscription URL on your behalf, so avoid sending sensitive subscriptions to untrusted public instances.
