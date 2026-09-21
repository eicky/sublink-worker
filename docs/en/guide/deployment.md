# Deployment

All deployment targets use the same Hono application. They mainly differ in persistence, static asset handling, and platform entry points.

## Standalone packages

Each release provides Windows, Linux, and macOS x64 packages containing the executable and `public/` assets.

1. Download the matching package from [GitHub Releases](https://github.com/eicky/sublink-worker/releases).
2. Verify it against `SHA256SUMS.txt`.
3. Extract and run it from that directory:

```sh
# Linux / macOS
./sublink-worker

# Windows PowerShell
.\sublink-worker.exe
```

The default port is `8787`. Without Redis or a Redis REST service, the process uses in-memory storage and loses saved configurations and short links after restart.

## Docker Compose

```sh
git clone https://github.com/eicky/sublink-worker.git
cd sublink-worker
docker compose up -d
```

The default image is `ghcr.io/eicky/sublink-worker:latest`. Update with:

```sh
docker compose pull
docker compose up -d
```

Pin a release when stability matters:

```sh
SUBLINK_WORKER_IMAGE=ghcr.io/eicky/sublink-worker:v3.0.0 docker compose up -d
```

## Cloudflare Workers

Use the [one-click deployment](https://deploy.workers.cloudflare.com/?url=https://github.com/eicky/sublink-worker), or deploy from a checkout:

```sh
npm ci
npx wrangler login
npm run deploy
```

The deployment script finds or creates `SUBLINK_KV` in the active account and updates its binding. GitHub Actions deployment requires `CLOUDFLARE_API_TOKEN` and `CF_ACCOUNT_ID`; without both secrets, the workflow skips deployment.

## Vercel

Use the [Vercel import page](https://vercel.com/new/clone?repository-url=https://github.com/eicky/sublink-worker&env=KV_REST_API_URL,KV_REST_API_TOKEN). Configure `KV_REST_API_URL` and `KV_REST_API_TOKEN`, or use `REDIS_URL`, for persistent storage.

Serverless memory is not shared reliably between instances and should not be used for persistent short links.

## Node.js

```sh
npm ci
npm run build:node
node dist/node-server.cjs
```

Static files default to `public/`. Set `STATIC_DIR` to an absolute path when starting the bundle from another working directory.

## GitHub Pages

GitHub Pages publishes documentation only and does not execute conversion endpoints. The Pages workflow deploys this site to:

```text
https://eicky.github.io/sublink-worker/
```
