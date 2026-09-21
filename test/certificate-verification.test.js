import { afterEach, describe, expect, it, vi } from 'vitest';
import yaml from 'js-yaml';
import { createApp } from '../src/app/createApp.jsx';
import { MemoryKVAdapter } from '../src/adapters/kv/memoryKv.js';
import { SING_BOX_CONFIG, CLASH_CONFIG } from '../src/config/index.js';
import { buildClashProxy } from '../src/builders/helpers/clashProxy.js';
import { buildSingboxProxy } from '../src/builders/helpers/singboxProxy.js';

const uuid = 'd342d11e-d424-4583-b36e-524ab1f0afa4';
const pin = 'ab'.repeat(32);
const pinned = `vless://${uuid}@node.example:443?security=tls&sni=node.example&fp=chrome&alpn=h2&pcs=${pin}#Pinned`;
const app = createApp({ kv: new MemoryKVAdapter(), logger: { error: vi.fn(), warn: vi.fn(), info: vi.fn() } });
const request = (target, config, options = {}) => app.request(`http://localhost/${target}?${new URLSearchParams({ config, ...options })}`);
const parse = async (target, response) => target === 'clash' ? yaml.load(await response.text()) : response.json();
const nodes = (target, config) => target === 'clash' ? config.proxies : config.outbounds.filter(proxy => proxy.server);

function expectSkipped(target, proxy) {
    if (target === 'clash') {
        expect(proxy['skip-cert-verify']).toBe(true);
        expect(proxy).not.toHaveProperty('fingerprint');
    } else {
        expect(proxy.tls.insecure).toBe(true);
        for (const key of ['certificate_sha256', 'certificate_public_key_sha256', 'certificate', 'certificate_path']) expect(proxy.tls).not.toHaveProperty(key);
    }
}

afterEach(() => vi.unstubAllGlobals());

describe('proxy certificate verification policy', () => {
    it.each(['false', '1', 'yes'])('preserves subscription verification for skip_cert_verify=%s', async flag => {
        const options = { skip_cert_verify: flag };
        const clash = await request('clash', pinned, options);
        expect(clash.status).toBe(200);
        expect(nodes('clash', await parse('clash', clash))[0]).toMatchObject({ fingerprint: pin, 'skip-cert-verify': false });
        const singbox = await request('singbox', pinned, options);
        expect(singbox.status).toBe(400);
        expect(await singbox.text()).toMatch(/certificate fingerprint pinning/);
    });

    it.each(['clash', 'singbox'].flatMap(target => [undefined, 'true'].map(flag => [target, flag])))('%s skips verification for skip_cert_verify=%s and preserves TLS identity settings', async (target, flag) => {
        const response = await request(target, pinned, flag === undefined ? {} : { skip_cert_verify: flag });
        expect(response.status).toBe(200);
        const proxy = nodes(target, await parse(target, response))[0];
        expectSkipped(target, proxy);
        expect(proxy.uuid).toBe(uuid);
        if (target === 'clash') expect(proxy).toMatchObject({ servername: 'node.example', alpn: ['h2'], 'client-fingerprint': 'chrome' });
        else expect(proxy.tls).toMatchObject({ enabled: true, server_name: 'node.example', alpn: ['h2'], utls: { enabled: true, fingerprint: 'chrome' } });
    });

    it.each(['clash', 'singbox'])('%s converts pinned Hysteria2 when verification is explicitly skipped', async target => {
        const response = await request(target, `hy2://password@node.example:443?sni=node.example&pinSHA256=${pin}#Pinned-HY2`, { skip_cert_verify: 'true' });
        expect(response.status).toBe(200);
        const proxy = nodes(target, await parse(target, response))[0];
        expectSkipped(target, proxy);
        expect(proxy.password).toBe('password');
    });

    it.each(['clash', 'singbox'])('%s does not enable plaintext TLS or weaken REALITY', async target => {
        const input = [`vless://${uuid}@node.example:80?security=none#Plain`, `vless://${uuid}@node.example:443?security=reality&pbk=public-key&sid=abcd&fp=chrome&sni=node.example#Reality`].join('\n');
        const baseline = nodes(target, await parse(target, await request(target, input, { skip_cert_verify: 'false' })));
        const response = await request(target, input, { skip_cert_verify: 'true' });
        expect(response.status).toBe(200);
        expect(nodes(target, await parse(target, response))).toEqual(baseline);
    });

    it('does not mutate source TLS constraints or remove client authentication', () => {
        const proxy = { type: 'vless', tag: 'Pinned', server: 'node.example', server_port: 443, uuid, tls: { enabled: true, insecure: false, certificate_sha256: pin, certificate_public_key_sha256: ['public-key-pin'], certificate: ['custom-ca'], certificate_path: '/custom-ca.pem', client_certificate: ['client-cert'], client_key: ['client-key'] } };
        const original = structuredClone(proxy);
        expectSkipped('clash', buildClashProxy(proxy, true));
        const converted = buildSingboxProxy(proxy, '1.14', true);
        expectSkipped('singbox', converted);
        expect(converted.tls).toMatchObject({ client_certificate: ['client-cert'], client_key: ['client-key'] });
        expect(proxy).toEqual(original);
    });

    it.each(['clash', 'singbox'])('%s inlines compatible remote subscriptions so provider passthrough cannot bypass the override', async target => {
        const source = target === 'clash'
            ? yaml.dump({ proxies: [{ name: 'Remote', type: 'vless', server: 'node.example', port: 443, uuid, tls: true, fingerprint: pin }] })
            : JSON.stringify({ outbounds: [{ tag: 'Remote', type: 'vless', server: 'node.example', server_port: 443, uuid, tls: { enabled: true, certificate_public_key_sha256: ['public-key-pin'] } }] });
        vi.stubGlobal('fetch', vi.fn(async () => new Response(source)));
        const response = await request(target, 'https://subscription.example/nodes', { skip_cert_verify: 'true' });
        expect(response.status).toBe(200);
        const config = await parse(target, response);
        expect(nodes(target, config)).toHaveLength(1);
        expectSkipped(target, nodes(target, config)[0]);
        expect(config[target === 'clash' ? 'proxy-providers' : 'outbound_providers']).toBeUndefined();
    });

    it.each(['clash', 'singbox'])('%s applies the override to stored base-config proxy nodes without changing the stored config', async target => {
        const base = target === 'clash'
            ? { ...CLASH_CONFIG, proxies: [{ name: 'Base', type: 'trojan', server: 'node.example', port: 443, password: 'password', fingerprint: pin }] }
            : { ...SING_BOX_CONFIG, outbounds: [...SING_BOX_CONFIG.outbounds, { tag: 'Base', type: 'trojan', server: 'node.example', server_port: 443, password: 'password', tls: { enabled: true, certificate_public_key_sha256: ['public-key-pin'], certificate: ['custom-ca'], certificate_path: '/custom-ca.pem' } }] };
        const saved = await app.request('http://localhost/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ type: target, content: base }) });
        expect(saved.status).toBe(200);
        const configId = await saved.text();
        const input = `vless://${uuid}@node.example:80?security=none#Plain`;
        const response = await request(target, input, { configId, skip_cert_verify: 'true' });
        expect(response.status).toBe(200);
        const baseProxy = nodes(target, await parse(target, response)).find(proxy => (proxy.name || proxy.tag) === 'Base');
        expectSkipped(target, baseProxy);
        const unchanged = nodes(target, await parse(target, await request(target, input, { configId, skip_cert_verify: 'false' }))).find(proxy => (proxy.name || proxy.tag) === 'Base');
        if (target === 'clash') expect(unchanged.fingerprint).toBe(pin);
        else expect(unchanged.tls.certificate_public_key_sha256).toEqual(['public-key-pin']);
    });

    it.each(['clash', 'singbox'])('%s rejects preconfigured providers instead of silently leaving their verification unchanged', async target => {
        const config = target === 'clash'
            ? yaml.dump({ proxies: [{ name: 'Inline', type: 'trojan', server: 'node.example', port: 443, password: 'password' }], 'proxy-providers': { existing: { type: 'http', url: 'https://subscription.example/provider' } } })
            : JSON.stringify({ outbounds: [{ tag: 'Inline', type: 'trojan', server: 'node.example', server_port: 443, password: 'password', tls: { enabled: true } }], outbound_providers: [{ tag: 'existing', type: 'http', download_url: 'https://subscription.example/provider' }] });
        const response = await request(target, config, { skip_cert_verify: 'true' });
        expect(response.status).toBe(400);
        expect(await response.text()).toMatch(/skip_cert_verify.*providers/i);
    });

    it.each(['true', 'false'])('preserves skip_cert_verify=%s through short links and resolution', async flag => {
        const url = `http://localhost/clash?${new URLSearchParams({ config: pinned, skip_cert_verify: flag })}`;
        const shortened = await app.request(`http://localhost/shorten-v2?${new URLSearchParams({ url })}`);
        expect(shortened.status).toBe(200);
        const code = await shortened.text();
        const shortUrl = `http://localhost/c/${code}`;
        const redirect = await app.request(shortUrl);
        expect(new URL(redirect.headers.get('Location')).searchParams.get('skip_cert_verify')).toBe(flag);
        const result = await app.request(redirect.headers.get('Location'));
        expect(result.status).toBe(200);
        const proxy = nodes('clash', await parse('clash', result))[0];
        if (flag === 'true') expectSkipped('clash', proxy);
        else expect(proxy).toMatchObject({ fingerprint: pin, 'skip-cert-verify': false });
        const resolved = await app.request(`http://localhost/resolve?${new URLSearchParams({ url: shortUrl })}`);
        expect(new URL((await resolved.json()).originalUrl).searchParams.get('skip_cert_verify')).toBe(flag);
    });
});
