import { afterEach, describe, expect, it, vi } from 'vitest';
import yaml from 'js-yaml';
import { encodeBase64 } from '../src/utils.js';
import { fetchSubscriptionWithFormat } from '../src/parsers/subscription/httpSubscriptionFetcher.js';
import { SingboxConfigBuilder } from '../src/builders/SingboxConfigBuilder.js';
import { ClashConfigBuilder } from '../src/builders/ClashConfigBuilder.js';

const password = 'p@ss?#:/%20';
const uri = `trojan://${encodeURIComponent(password)}@node.example:443?peer=sni.example&alpn=h2%2Chttp%2F1.1#Node`;
const remote = 'https://subscription.example.test/nodes';
const encodings = [
    ['plain', value => value],
    ['base64', value => encodeBase64(value)],
    ['URI envelope', value => encodeURIComponent(value)],
    ['base64 URI envelope', value => encodeBase64(encodeURIComponent(value))]
];

function mockSubscription(body) {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(body, { headers: { 'subscription-userinfo': 'upload=1; download=2; total=1000' } })));
}

afterEach(() => vi.unstubAllGlobals());

describe('subscription envelope decoding preserves node encoding', () => {
    it.each(encodings)('keeps escaped credentials intact in a %s subscription', async (_name, wrap) => {
        mockSubscription(wrap(uri));
        const result = await fetchSubscriptionWithFormat(remote);
        expect(result.content).toBe(uri);
    });

    it.each(encodings)('builds usable sing-box credentials from a %s subscription', async (_name, wrap) => {
        mockSubscription(wrap(uri));
        const builder = new SingboxConfigBuilder(remote, 'minimal', [], null, 'en', null);
        await builder.build();
        const proxy = builder.getProxies().find(proxy => proxy.tag === 'Node');
        expect(proxy).toMatchObject({ type: 'trojan', password, server: 'node.example', server_port: 443, tls: { enabled: true, server_name: 'sni.example', alpn: ['h2', 'http/1.1'] } });
        expect(proxy.transport).toBeUndefined();
        expect(builder.getSubscriptionUserinfo()).toBe('upload=1; download=2; total=1000');
    });

    it('does not silently drop a malformed protocol node fetched from a subscription', async () => {
        mockSubscription('trojan://password@node.example:invalid#Broken');
        await expect(new SingboxConfigBuilder(remote, 'minimal', [], null, 'en', null).build()).rejects.toThrow(/port/i);
    });

    it('does not swallow invalid protocol fields in direct or base64 YAML', async () => {
        const content = 'proxies:\n  - name: Broken\n    type: trojan\n    server: node.example\n    port: 70000\n    password: pass';
        for (const input of [content, encodeBase64(content)]) {
            await expect(new SingboxConfigBuilder(input, 'minimal', [], null, 'en', null).build()).rejects.toThrow(/port/i);
        }
    });

    it('keeps native sing-box nodes that omit the optional tag', async () => {
        const input = JSON.stringify({ outbounds: [{ type: 'trojan', server: 'node.example', server_port: 443, password: 'pass', tls: { enabled: true } }] });
        const config = await new SingboxConfigBuilder(input, 'minimal', [], null, 'en', null).build();
        expect(config.outbounds.find(proxy => proxy.type === 'trojan')).toMatchObject({ tag: 'node.example:443', password: 'pass' });
    });

    it('does not copy foreign sing-box DNS and route objects into Mihomo output', async () => {
        const input = JSON.stringify({ dns: { servers: [{ type: 'udp', server: '1.1.1.1' }] }, route: { final: 'Test' }, outbounds: [{ type: 'trojan', tag: 'Test', server: 'node.example', server_port: 443, password: 'pass', tls: { enabled: true } }] });
        const config = yaml.load(await new ClashConfigBuilder(input, 'minimal', [], null, 'en', null).build());
        expect(config).not.toHaveProperty('route');
        expect(config.dns).not.toHaveProperty('servers');
        expect(config.proxies[0].password).toBe('pass');
    });

    it('does not copy foreign Mihomo listener and DNS fields into sing-box output', async () => {
        const input = 'mixed-port: 7890\ndns:\n  nameserver: [1.1.1.1]\nproxies:\n  - { name: Test, type: trojan, server: node.example, port: 443, password: pass }';
        const config = await new SingboxConfigBuilder(input, 'minimal', [], null, 'en', null).build();
        expect(config).not.toHaveProperty('mixed-port');
        expect(config.dns).not.toHaveProperty('nameserver');
        expect(config.outbounds.some(proxy => proxy.tag === 'Test')).toBe(true);
    });

    it('preserves the same password when emitting Mihomo', async () => {
        mockSubscription(encodeBase64(uri));
        const builder = new ClashConfigBuilder(remote, 'minimal', [], null, 'en', null);
        const config = yaml.load(await builder.build());
        expect(config.proxies[0]).toMatchObject({ type: 'trojan', password, sni: 'sni.example', alpn: ['h2', 'http/1.1'] });
    });

    it('does not URI-decode strings inside plain YAML and JSON configurations', async () => {
        const formats = [
            'proxies:\n  - name: Test\n    type: trojan\n    server: node.example\n    port: 443\n    password: "literal%2Fpassword"',
            JSON.stringify({ outbounds: [{ type: 'trojan', tag: 'Test', server: 'node.example', server_port: 443, password: 'literal%2Fpassword', tls: { enabled: true } }] })
        ];
        for (const text of formats) {
            mockSubscription(text);
            expect((await fetchSubscriptionWithFormat(remote)).content).toBe(text);
        }
    });
});
