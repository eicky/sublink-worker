# Protocol Support

This page is a concise English overview. The [canonical matrix](/protocol-support) contains the complete field-level contracts, validation commands, and primary-source references.

| Protocol | Share-link input | Mihomo | sing-box | Surge |
|---|---|---|---|---|
| Shadowsocks | `ss://` | Supported | Supported, with target plugin limits | Supported ciphers and simple-obfs |
| ShadowsocksR | `ssr://` | Supported | Not supported; removed in 1.6 | Not supported |
| VMess | v2rayN JSON and authority-style URI | Supported when the transport is representable | Supported when the transport is representable | TCP / WebSocket subset |
| VLESS | `vless://` | Supported, including basic XHTTP | No new VLESS encryption or XHTTP | Not supported |
| Trojan | `trojan://` | TCP, WS/HTTPUpgrade, gRPC | TCP, WS, HTTP/H2, HTTPUpgrade, gRPC | TCP / WebSocket |
| Hysteria v1 | `hysteria://` | Supported | UDP-compatible subset | Not supported |
| Hysteria2 / HY2 | `hysteria2://`, `hy2://` | Supported | Supported with version gates | Supported subset |
| TUIC | Project v5 UUID/password profile | v5 | v5 | Native v4/v5 input; target limits apply |
| AnyTLS | `anytls://` | Supported except REALITY | Requires sing-box 1.12+ | Supported subset |

## Important semantics

- `hysteria://` is v1; `hysteria2://` and `hy2://` are v2.
- ShadowsocksR is never downgraded to Shadowsocks.
- TLS SNI, HTTP Host, uTLS fingerprints, whole-certificate hashes, and public-key hashes are distinct fields. When preserving the subscription's verification policy, a single VLESS/VMess `pcs` certificate pin maps to Mihomo `fingerprint`; sing-box rejects an unrepresentable whole-certificate pin rather than replacing it with a public-key pin. The UI and `/clash` / `/singbox` default to the verification override below, which removes these constraints instead.
- Xray gRPC `mode=multi` links can use the same server through Mihomo/sing-box's native `Tun` method: Xray exposes both `Tun` and `TunMulti`. Service names and TLS/REALITY settings are preserved, but the multi framing implementation is not. A reverse proxy restricted to `TunMulti` paths still needs a server-side routing change. `guna` and unrepresentable custom authorities remain unsupported.
- A sing-box `network` field restricts TCP/UDP; it is not a WS/gRPC transport selector.
- Disabled TLS is omitted entirely from sing-box output. In sing-box 1.14.1, some native outbounds select a TLS dialer by block presence; `tls: { enabled: false }` can pass configuration checks but crash on the first connection.
- Unsupported combinations fail explicitly or become non-selectable `Unsupported` comments in Surge output.

## Certificate verification policy

**Enabled by default** in the UI and `/clash` / `/singbox` to prioritize compatibility, including older conversion links without this parameter. To preserve the subscription's original verification policy, disable **Skip proxy server certificate verification** under Advanced Options → General Settings, or append `skip_cert_verify=false`.

- Sets Mihomo `skip-cert-verify: true` / sing-box `tls.insecure: true` and removes certificate pins, public-key pins and custom server CA constraints, including imported `pcs` / `pinSHA256` pins. **The proxy server's identity is no longer verified.**
- Preserves encryption, SNI, ALPN, uTLS fingerprints and client certificates. Plaintext and REALITY nodes are unchanged.
- Compatible remote subscriptions are inlined so the override cannot be bypassed by provider passthrough. Refresh the converted subscription to update nodes. Stored base-config proxy nodes are also processed; preconfigured remote providers must be inlined first or the request fails explicitly.
- Preserved in generated links, short links, restored links and local form preferences. New links explicitly include `true` or `false`, and saved opt-out preferences remain respected. `false` preserves the subscription's original policy, including existing insecure settings.
- Applies only to native proxy TLS settings, not Shadowsocks plugins, subscription downloads, rule downloads or DNS. It does not affect Surge or `/xray` Base64 output.

Xray 26.3.27 rejects `allowInsecure=true` after its date gate. Removing it **restores verification**, rather than bypassing it; certificate pins and SNI must still be preserved. `/xray` continues to return original share links, not rewritten native Xray JSON.

For exact transport mappings, version gates, ECH and certificate pin behavior, read the [full protocol contract](/protocol-support).
