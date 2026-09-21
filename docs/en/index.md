---
layout: home

hero:
  name: Sublink Worker
  text: One subscription, multiple clients
  tagline: Normalize share links and client configurations into Mihomo, sing-box, Surge, or Base64 URI subscriptions. Deploy on Workers, Vercel, Node.js, Docker, or as a standalone package.
  image:
    src: /logo.svg
    alt: Sublink Worker
  actions:
    - theme: brand
      text: Get Started
      link: /en/guide/getting-started
    - theme: alt
      text: Deploy
      link: /en/guide/deployment
    - theme: alt
      text: Protocol Support
      link: /en/protocol-support

features:
  - icon: ⇄
    title: One conversion interface
    details: Parse share links, remote subscriptions, Mihomo YAML, sing-box JSON, and Surge INI before adapting them to a target client.
  - icon: ◈
    title: Explicit compatibility limits
    details: Protocol generations, TLS, transports, and client extensions stay distinct. Unsupported mappings fail clearly instead of silently losing fields.
  - icon: ⎈
    title: Multiple runtimes
    details: Run the same Hono application on Cloudflare Workers, Vercel, Node.js, Docker, or from a standalone release package.
  - icon: ◇
    title: Optional persistence
    details: Use Cloudflare KV, Redis, Redis REST, or in-memory storage for base configurations and short links.
  - icon: ◎
    title: Automated verification
    details: Parser, builder, subscription, and HTTP endpoint tests are complemented by optional sing-box and Mihomo configuration checks.
  - icon: ⚙
    title: Self-hosted by design
    details: This documentation site never receives subscription data. Conversion requests only go to the service instance you choose.
---

## Documentation and service architecture

GitHub Pages hosts documentation only. Deploy the actual converter to one of the supported runtimes:

```text
GitHub Pages                 Documentation and deployment guides
Cloudflare / Vercel / Node   Web UI, conversion endpoints, short links
GitHub Container Registry    amd64 / arm64 Docker images
GitHub Releases              Windows / Linux / macOS standalone packages
```

::: tip Start here
Read the [overview](/en/guide/getting-started), select a [deployment method](/en/guide/deployment), and consult [protocol support](/en/protocol-support) when a target client cannot represent a node.
:::
