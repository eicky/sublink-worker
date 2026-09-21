# Configuration

## Storage selection

Node.js, Docker, and Vercel select storage in this order:

1. Redis through `REDIS_URL`, or `REDIS_HOST` plus `REDIS_PORT`
2. Redis REST through `KV_REST_API_URL` plus `KV_REST_API_TOKEN`
3. In-memory storage

Set `DISABLE_MEMORY_KV=true` to make missing external storage explicit. Cloudflare Workers use the `SUBLINK_KV` binding.

## Environment variables

| Variable | Purpose |
|---|---|
| `PORT` | HTTP port, default `8787` |
| `STATIC_DIR` | Static asset directory, default `public` |
| `REDIS_URL` | Complete `redis://` or `rediss://` URL |
| `REDIS_HOST`, `REDIS_PORT` | Redis host and port when no URL is used |
| `REDIS_USERNAME`, `REDIS_PASSWORD` | Optional Redis credentials |
| `REDIS_TLS` | Set to `true` to enable Redis TLS options |
| `REDIS_KEY_PREFIX` | Prefix used to isolate data in a shared Redis instance |
| `KV_REST_API_URL`, `KV_REST_API_TOKEN` | Redis-compatible REST storage |
| `DISABLE_MEMORY_KV` | Set to `true` to disable the in-memory fallback |
| `CONFIG_TTL_SECONDS` | Saved configuration lifetime; `0` means no expiration |
| `SHORT_LINK_TTL_SECONDS` | Short-link lifetime in seconds |

Keep credentials in deployment secrets or local environment files that are not committed to Git.

## Cloudflare KV

`wrangler.toml` needs a binding for the namespace in your own Cloudflare account:

```toml
kv_namespaces = [
  { binding = "SUBLINK_KV", id = "<YOUR_NAMESPACE_ID>" }
]
```

Do not copy another account's namespace ID. `npm run deploy` can locate or create the namespace for the currently authenticated account.
