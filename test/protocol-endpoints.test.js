import { afterEach, describe, expect, it, vi } from 'vitest';
import yaml from 'js-yaml';
import { createApp } from '../src/app/createApp.jsx';
import { MemoryKVAdapter } from '../src/adapters/kv/memoryKv.js';
import { encodeBase64 } from '../src/utils.js';

const uuid = 'd342d11e-d424-4583-b36e-524ab1f0afa4';
const b64 = value => encodeBase64(value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const fixtures = [
    ['ss', `ss://${b64('aes-128-gcm:password')}@node.example:443#API-node`, 'ss', 'shadowsocks'],
    ['ssr', `ssr://${b64(`node.example:443:auth_aes128_md5:aes-128-cfb:tls1.2_ticket_auth:${b64('password')}/?remarks=${b64('API-node')}`)}`, 'ssr', null],
    ['vmess', `vmess://${b64(JSON.stringify({ v: '2', ps: 'API-node', add: 'node.example', port: '443', id: uuid, aid: '0', scy: 'auto', net: 'ws', path: '/ws', tls: 'tls' }))}`, 'vmess', 'vmess'],
    ['vless', `vless://${uuid}@node.example:443?security=tls#API-node`, 'vless', 'vless'],
    ['trojan', 'trojan://password@node.example:443#API-node', 'trojan', 'trojan'],
    ['hysteria', 'hysteria://node.example:443?auth=password&upmbps=10&downmbps=50#API-node', 'hysteria', 'hysteria'],
    ['hysteria2', 'hysteria2://password@node.example:443#API-node', 'hysteria2', 'hysteria2'],
    ['hy2', 'hy2://password@node.example:443#API-node', 'hysteria2', 'hysteria2'],
    ['tuic', `tuic://${uuid}:password@node.example:443?alpn=h3#API-node`, 'tuic', 'tuic'],
    ['anytls', 'anytls://password@node.example:443#API-node', 'anytls', 'anytls']
];
const app = createApp({
    kv: new MemoryKVAdapter(),
    logger: { error: vi.fn(), warn: vi.fn(), info: vi.fn() },
    config: { configTtlSeconds: 60, shortLinkTtlSeconds: null }
});

function request(path, config, extra = {}) {
    return app.request(`http://localhost${path}?${new URLSearchParams({ config, ...extra })}`);
}

afterEach(() => vi.unstubAllGlobals());

describe('public conversion endpoints', () => {
    it('aggregates subscriptions containing gRPC multi and certificate-pinned VLESS without losing nodes', async () => {
        const pin = 'ab'.repeat(32);
        const subscriptions = new Map([
            ['https://subscription.example/one', encodeBase64(`vless://${uuid}@node.example:443?security=reality&pbk=public-key&sid=abcd&fp=chrome&type=grpc&serviceName=example&mode=multi#Grpc-multi`)],
            ['https://subscription.example/two', encodeBase64(`vless://${uuid}@node.example:443?security=tls&insecure=0&pcs=${pin}#Pinned`)],
            ['https://subscription.example/three', encodeBase64('trojan://password@node.example:443#Trojan')]
        ]);
        vi.stubGlobal('fetch', vi.fn(async url => new Response(subscriptions.get(String(url)), { status: subscriptions.has(String(url)) ? 200 : 404 })));
        const response = await request('/clash', [...subscriptions.keys()].join('\n'), { include_auto_select: 'false', skip_cert_verify: 'false' });
        expect(response.status).toBe(200);
        const config = yaml.load(await response.text());
        expect(config.proxies).toHaveLength(3);
        expect(config.proxies).toEqual(expect.arrayContaining([
            expect.objectContaining({ name: 'Grpc-multi', network: 'grpc', 'grpc-opts': { 'grpc-service-name': 'example' }, 'reality-opts': { 'public-key': 'public-key', 'short-id': 'abcd' } }),
            expect.objectContaining({ name: 'Pinned', fingerprint: pin, 'skip-cert-verify': false }),
            expect.objectContaining({ name: 'Trojan', type: 'trojan' })
        ]));
        expect(config['proxy-groups'].some(group => ['Grpc-multi', 'Pinned', 'Trojan'].every(name => group.proxies?.includes(name)))).toBe(true);
    });

    it.each(fixtures)('keeps a selectable %s node in Mihomo output', async (_scheme, uri, expectedType) => {
        const response = await request('/clash', uri);
        expect(response.status).toBe(200);
        expect(yaml.load(await response.text()).proxies).toContainEqual(expect.objectContaining({ name: 'API-node', type: expectedType, server: 'node.example', port: 443 }));
    });

    it('converts gRPC multi to a sing-box transport without Xray-only mode fields', async () => {
        const response = await request('/singbox', `vless://${uuid}@node.example:443?security=tls&type=grpc&serviceName=example&mode=multi#Grpc`, { singbox_version: '1.14' });
        expect(response.status).toBe(200);
        expect((await response.json()).outbounds.find(proxy => proxy.tag === 'Grpc').transport).toEqual({ type: 'grpc', service_name: 'example' });
    });

    it.each(fixtures)('handles %s according to the sing-box capability contract', async (_scheme, uri, _clashType, expectedType) => {
        const response = await request('/singbox', uri, { singbox_version: '1.14' });
        if (!expectedType) {
            expect(response.status).toBe(400);
            expect(await response.text()).toMatch(/ShadowsocksR.*removed/i);
        } else {
            expect(response.status).toBe(200);
            expect((await response.json()).outbounds).toContainEqual(expect.objectContaining({ tag: 'API-node', type: expectedType, server: 'node.example', server_port: 443 }));
        }
    });

    it('reports malformed credentials without reflecting the secret URI', async () => {
        const secret = 'do-not-reflect-this-password';
        const response = await request('/singbox', `trojan://${secret}@node.example:70000#Broken`);
        expect(response.status).toBe(400);
        const body = await response.text();
        expect(body).toMatch(/port/i);
        expect(body).not.toContain(secret);
    });

    it('rejects AnyTLS for an older sing-box target instead of emitting an unknown outbound', async () => {
        const response = await request('/singbox', fixtures.at(-1)[1], { singbox_version: '1.11' });
        expect(response.status).toBe(400);
        expect(await response.text()).toMatch(/AnyTLS.*1\.12/);
    });

    it('reports an unsupported scheme instead of returning an empty proxy configuration', async () => {
        const response = await request('/singbox', 'hysteria2+realm://node.example:443#Unsupported');
        expect(response.status).toBe(400);
        expect(await response.text()).toMatch(/Unsupported proxy protocol/);
    });

    it('emits the currently supported Surge AnyTLS policy', async () => {
        const response = await request('/surge', fixtures.at(-1)[1]);
        expect(response.status).toBe(200);
        expect(await response.text()).toContain('API-node = anytls, node.example, 443, password=password');
    });

    it('builds Surge output when automatic selection is disabled', async () => {
        const response = await request('/surge', fixtures[0][1], { include_auto_select: 'false' });
        expect(response.status).toBe(200);
        const config = await response.text();
        expect(config).toContain('[Proxy Group]');
        expect(config).toContain('API-node');
        expect(config).not.toContain('url-test');
    });
});
