# FAQ

## Can GitHub Pages perform conversions?

No. GitHub Pages hosts static documentation only. Deploy the converter to Workers, Vercel, Node.js, Docker, or use a standalone package.

## Why is `/xray` not Xray JSON?

It returns a Base64-encoded list of share links for subscription compatibility. It does not build Xray JSON and does not imply that Xray supports every input protocol.

## Why can a node not be exported to every client?

Client capabilities differ. Current sing-box versions removed ShadowsocksR, Surge does not support VLESS, and several TLS, transport, hopping, and plugin fields have no equivalent representation. The converter rejects lossy mappings instead of pretending they are compatible.

## What is the difference between `hysteria://` and `hy2://`?

`hysteria://` is Hysteria v1. `hysteria2://` and `hy2://` are Hysteria v2. Their fields are not interchangeable.

## Why does SSR fail for sing-box?

sing-box removed ShadowsocksR in version 1.6. The project can export SSR to Mihomo, but never downgrades it to Shadowsocks.

## The standalone UI is blank or returns 404

Keep the executable and `public/` directory together and launch it from the extracted directory. Otherwise set `STATIC_DIR` to the absolute path of `public/`.

## Why did a short link disappear after restart?

The instance was using in-memory storage. Configure Redis, Redis REST, or Cloudflare KV for persistent data.

## How do I update?

- Docker Compose: `docker compose pull && docker compose up -d`
- Standalone package: replace the extracted directory with the new release
- Workers or Vercel: synchronize `main` and redeploy
- Source checkout: pull changes, run `npm ci`, and rebuild

## How should I report a protocol issue?

Open a [GitHub issue](https://github.com/eicky/sublink-worker/issues) with the input format, target client and version, a minimal fixture using fictional credentials, and the exact error. Never include a real subscription token or password.
