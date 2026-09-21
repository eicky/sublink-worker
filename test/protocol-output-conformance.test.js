import { describe, expect, it } from 'vitest';
import { ClashConfigBuilder } from '../src/builders/ClashConfigBuilder.js';
import { SingboxConfigBuilder } from '../src/builders/SingboxConfigBuilder.js';
import { SurgeConfigBuilder } from '../src/builders/SurgeConfigBuilder.js';
import { convertYamlProxyToObject } from '../src/parsers/convertYamlProxyToObject.js';
import { convertSurgeProxyToObject } from '../src/parsers/convertSurgeProxyToObject.js';
import { parseTrojan } from '../src/parsers/protocols/trojanParser.js';
import { parseVless } from '../src/parsers/protocols/vlessParser.js';

const uuid = 'd342d11e-d424-4583-b36e-524ab1f0afa4';
const base = { tag: 'Test', server: 'node.example', server_port: 443 };
const clash = () => new ClashConfigBuilder('', [], [], null, 'en', null);
const singbox = () => new SingboxConfigBuilder('', [], [], null, 'en', null);
const surge = () => new SurgeConfigBuilder('', [], [], null, 'en', null);

describe('Clash YAML input preserves protocol semantics', () => {
    it('does not disable Trojan TLS when the redundant tls flag is omitted', () => {
        const parsed = convertYamlProxyToObject({ name: 'Trojan', type: 'trojan', server: 'node.example', port: 443, password: 'pass', sni: 'sni.example', alpn: ['h2', 'http/1.1'] });
        expect(parsed.tls).toMatchObject({ enabled: true, server_name: 'sni.example', alpn: ['h2', 'http/1.1'] });
    });

    it.each(['vmess', 'vless', 'trojan', 'hysteria2', 'tuic', 'anytls'])('does not treat quoted false TLS verification flags as true (%s)', type => {
        const parsed = convertYamlProxyToObject({ name: type, type, server: 'node.example', port: 443, uuid, password: 'pass', tls: true, 'skip-cert-verify': 'false' });
        expect(parsed.tls.insecure).toBe(false);
    });

    it('preserves the VMess fingerprint and ALPN in TLS', () => {
        const parsed = convertYamlProxyToObject({ name: 'VMess', type: 'vmess', server: 'node.example', port: 443, uuid, tls: true, 'client-fingerprint': 'firefox', alpn: ['h2'] });
        expect(parsed.tls.utls).toEqual({ enabled: true, fingerprint: 'firefox' });
        expect(parsed.tls.alpn).toEqual(['h2']);
    });

    it('normalizes H2 separately from TCP HTTP obfuscation', () => {
        const input = { name: 'VMess', type: 'vmess', server: 'node.example', port: 443, uuid };
        const h2 = convertYamlProxyToObject({ ...input, network: 'h2', 'h2-opts': { host: ['cdn.example'], path: '/h2' } });
        const obfs = convertYamlProxyToObject({ ...input, network: 'http', 'http-opts': { path: ['/cover'], headers: { Host: ['cdn.example'] } } });
        expect(h2.transport).toMatchObject({ type: 'http', host: ['cdn.example'], path: '/h2' });
        expect(obfs.transport.type).toBe('http-obfs');
    });

    it('preserves WebSocket early-data settings', () => {
        const parsed = convertYamlProxyToObject({ name: 'VLESS', type: 'vless', server: 'node.example', port: 443, uuid, network: 'ws', 'ws-opts': { path: '/ws', headers: { Host: 'cdn.example' }, 'max-early-data': 2048, 'early-data-header-name': 'Sec-WebSocket-Protocol' } });
        expect(parsed.transport).toMatchObject({ type: 'ws', max_early_data: 2048, early_data_header_name: 'Sec-WebSocket-Protocol' });
    });

    it('does not conflate Hysteria v1 with v2', () => {
        const parsed = convertYamlProxyToObject({ name: 'HY1', type: 'hysteria', server: 'node.example', port: 443, 'auth-str': 'v1-password', up: 10, down: 50 });
        expect(parsed).toMatchObject({ type: 'hysteria', auth_str: 'v1-password', up_mbps: 10, down_mbps: 50 });
    });

    it('supports ShadowsocksR fields without reducing it to Shadowsocks', () => {
        const parsed = convertYamlProxyToObject({ name: 'SSR', type: 'ssr', server: 'node.example', port: 443, cipher: 'aes-128-cfb', password: 'pass', protocol: 'auth_aes128_md5', 'protocol-param': '123:secret', obfs: 'tls1.2_ticket_auth', 'obfs-param': 'cdn.example' });
        expect(parsed).toMatchObject({ type: 'shadowsocksr', method: 'aes-128-cfb', protocol: 'auth_aes128_md5', protocol_param: '123:secret', obfs: 'tls1.2_ticket_auth', obfs_param: 'cdn.example' });
    });
});

describe('target configuration adapters', () => {
    it.each(['trojan', 'vless', 'vmess'])('preserves ALPN and uTLS for %s in Mihomo output', type => {
        const converted = clash().convertProxy({ ...base, type, uuid, password: 'pass', security: 'auto', tls: { enabled: true, server_name: 'sni.example', alpn: ['h2', 'http/1.1'], utls: { enabled: true, fingerprint: 'firefox' } } });
        expect(converted.alpn).toEqual(['h2', 'http/1.1']);
        expect(converted['client-fingerprint']).toBe('firefox');
    });

    it('writes VLESS SNI using the pinned Mihomo VlessOption servername field', () => {
        const converted = clash().convertProxy(parseVless(`vless://${uuid}@node.example:443?security=tls&sni=sni.example#VLESS`));
        expect(converted.servername).toBe('sni.example');
        expect(converted).not.toHaveProperty('sni');
    });

    it.each(['vless', 'vmess', 'trojan'])('converts Xray gRPC multi to the compatible Mihomo Tun transport (%s)', type => {
        const proxy = { ...base, type, uuid, password: 'pass', tls: { enabled: true }, transport: { type: 'grpc', service_name: 'service.Name', mode: 'multi' } };
        const converted = clash().convertProxy(proxy);
        expect(converted.network).toBe('grpc');
        expect(converted['grpc-opts']).toEqual({ 'grpc-service-name': 'service.Name' });
        expect(proxy.transport.mode).toBe('multi');
    });

    it.each(['vless', 'vmess', 'trojan'])('converts Xray gRPC multi to the compatible sing-box Tun transport (%s)', type => {
        const proxy = { ...base, type, uuid, password: 'pass', tls: { enabled: true }, transport: { type: 'grpc', service_name: 'service.Name', mode: 'multi' } };
        expect(singbox().convertProxy(proxy).transport).toEqual({ type: 'grpc', service_name: 'service.Name' });
        expect(proxy.transport.mode).toBe('multi');
    });

    it.each(['guna', 'invalid'])('does not treat an unsupported gRPC mode as gun (%s)', mode => {
        for (const builder of [clash(), singbox()]) {
            expect(() => builder.convertProxy({ ...base, type: 'vless', uuid, transport: { type: 'grpc', mode } })).toThrow(/unsupported gRPC mode/);
        }
    });

    it('does not silently discard a custom gRPC authority', () => {
        for (const builder of [clash(), singbox()]) {
            expect(() => builder.convertProxy({ ...base, type: 'vless', uuid, transport: { type: 'grpc', mode: 'multi', authority: 'authority.example' } })).toThrow(/authority/);
        }
    });

    it('maps a VLESS certificate pin without confusing it with the TLS client fingerprint', () => {
        const pin = 'ab'.repeat(32);
        const converted = clash().convertProxy(parseVless(`vless://${uuid}@node.example:443?security=tls&sni=sni.example&fp=firefox&insecure=0&pcs=${pin}#Pinned`));
        expect(converted).toMatchObject({ fingerprint: pin, 'client-fingerprint': 'firefox', 'skip-cert-verify': false, servername: 'sni.example' });
        expect(() => singbox().convertProxy(parseVless(`vless://${uuid}@node.example:443?security=tls&pcs=${pin}`))).toThrow(/certificate fingerprint pinning/);
    });

    it('maps the canonical HTTP transport to Mihomo H2', () => {
        const converted = clash().convertProxy({ ...base, type: 'vmess', uuid, security: 'auto', transport: { type: 'http', host: ['cdn.example'], path: '/h2' }, tls: { enabled: true } });
        expect(converted.network).toBe('h2');
        expect(converted['h2-opts']).toEqual({ host: ['cdn.example'], path: '/h2' });
    });

    it('maps TCP HTTP obfuscation to Mihomo http instead of H2', () => {
        const converted = clash().convertProxy({ ...base, type: 'vmess', uuid, security: 'auto', transport: { type: 'http-obfs', path: ['/cover'], headers: { Host: ['cdn.example'] } } });
        expect(converted.network).toBe('http');
        expect(converted['http-opts']).toMatchObject({ path: ['/cover'], headers: { Host: ['cdn.example'] } });
    });

    it('preserves native sing-box Hysteria2 port hopping and bandwidth in Mihomo', () => {
        const converted = clash().convertProxy({ ...base, type: 'hysteria2', password: 'pass', server_ports: ['2000:3000', '443'], up_mbps: 10, down_mbps: 50, hop_interval: '10s', tls: { enabled: true } });
        expect(converted).toMatchObject({ ports: '2000-3000,443', up: 10, down: 50, 'hop-interval': 10 });
    });

    it('converts native sing-box AnyTLS durations back to Mihomo seconds', () => {
        const converted = clash().convertProxy({ ...base, type: 'anytls', password: 'pass', idle_session_check_interval: '30s', idle_session_timeout: '1m', min_idle_session: 2, tls: { enabled: true } });
        expect(converted['idle-session-check-interval']).toBe(30);
        expect(converted['idle-session-timeout']).toBe(60);
    });

    it('emits SSR in Mihomo format', () => {
        expect(clash().convertProxy({ ...base, type: 'shadowsocksr', method: 'aes-128-cfb', password: 'pass', protocol: 'auth_aes128_md5', protocol_param: '123:secret', obfs: 'tls1.2_ticket_auth', obfs_param: 'cdn.example' })).toMatchObject({ name: 'Test', type: 'ssr', port: 443, cipher: 'aes-128-cfb', protocol: 'auth_aes128_md5', 'protocol-param': '123:secret', obfs: 'tls1.2_ticket_auth', 'obfs-param': 'cdn.example' });
    });

    it.each(['vless', 'vmess'])('omits disabled TLS instead of constructing a native TLS dialer for plain %s', type => {
        for (const tls of [undefined, {}, { enabled: false }]) {
            expect(singbox().convertProxy({ ...base, type, uuid, tls })).not.toHaveProperty('tls');
        }
    });

    it('does not serialize an empty or legacy H2 transport into sing-box', () => {
        const converted = singbox().convertProxy({ ...base, type: 'vless', uuid, transport: { type: 'h2', host: ['cdn.example'], path: '/h2' }, tls: { enabled: true } });
        expect(converted.transport.type).toBe('http');
        expect(singbox().convertProxy({ ...base, type: 'trojan', password: 'pass', transport: {}, tls: { enabled: true } }).transport).toBeUndefined();
    });

    it('preserves the supported sing-box packet_encoding option', () => {
        const converted = singbox().convertProxy({ ...base, type: 'vless', uuid, packet_encoding: 'xudp' });
        expect(converted.packet_encoding).toBe('xudp');
    });

    it('rejects SSR rather than pretending a removed sing-box outbound is usable', () => {
        expect(() => singbox().convertProxy({ ...base, type: 'shadowsocksr', method: 'aes-128-cfb', password: 'pass', protocol: 'origin', obfs: 'plain' })).toThrow(/shadowsocksr|SSR/i);
    });

    it('does not export nonportable TUIC alias fields to sing-box', () => {
        const converted = singbox().convertProxy({ ...base, type: 'tuic', uuid, password: 'pass', zero_rtt: true, reduce_rtt: true, disable_sni: true, fast_open: true, tls: { enabled: true } });
        expect(converted.zero_rtt_handshake).toBe(true);
        expect(converted.tls.disable_sni).toBe(true);
        expect(converted).not.toHaveProperty('zero_rtt');
        expect(converted).not.toHaveProperty('reduce_rtt');
        expect(converted).not.toHaveProperty('disable_sni');
        expect(converted).not.toHaveProperty('fast_open');
    });

    it('normalizes Mihomo Gecko options and random hopping into sing-box 1.14 fields', () => {
        const parsed = convertYamlProxyToObject({ name: 'Gecko', type: 'hysteria2', server: 'node.example', port: 443, password: 'pass', ports: '443/2000-2005', 'hop-interval': '15-30', obfs: 'gecko', 'obfs-password': 'obfs-password', 'obfs-min-packet-size': 512, 'obfs-max-packet-size': 1200 });
        const builder = singbox();
        builder.singboxVersion = '1.14';
        expect(builder.convertProxy(parsed)).toMatchObject({ server_ports: ['443:443', '2000:2005'], hop_interval: '15s', hop_interval_max: '30s', obfs: { type: 'gecko', min_packet_size: 512, max_packet_size: 1200 } });
    });

    it('retains HTTPUpgrade headers instead of turning the connection into WebSocket', () => {
        const parsed = convertYamlProxyToObject({ name: 'Upgrade', type: 'vless', server: 'node.example', port: 443, uuid, network: 'ws', 'ws-opts': { 'v2ray-http-upgrade': true, path: '/upgrade', headers: { Host: 'cdn.example', 'X-Token': 'test-token' } } });
        expect(singbox().convertProxy(parsed).transport).toMatchObject({ type: 'httpupgrade', host: 'cdn.example', path: '/upgrade', headers: { 'X-Token': 'test-token' } });
        expect(clash().convertProxy(parsed)['ws-opts']).toMatchObject({ 'v2ray-http-upgrade': true, headers: { Host: 'cdn.example', 'X-Token': 'test-token' } });
    });

    it('preserves the two clients distinct TUIC defaults during conversion', () => {
        const native = { ...base, type: 'tuic', uuid, password: 'pass', tls: { enabled: true } };
        expect(clash().convertProxy(native)).toMatchObject({ 'congestion-controller': 'cubic', alpn: [] });
        const fromClash = convertYamlProxyToObject({ name: 'TUIC', type: 'tuic', server: 'node.example', port: 443, uuid, password: 'pass' });
        expect(singbox().convertProxy(fromClash)).toMatchObject({ congestion_control: 'new_reno', tls: { alpn: ['h3'] } });
    });

    it('preserves TCP-only arrays and refuses an unrepresentable UDP-only restriction', () => {
        const proxy = { ...base, type: 'vmess', uuid };
        expect(clash().convertProxy({ ...proxy, network: ['tcp'] }).udp).toBe(false);
        expect(() => clash().convertProxy({ ...proxy, network: 'udp' })).toThrow(/UDP-only/);
    });

    it('serializes Shadowsocks plugin options as the SIP003 option string for sing-box', () => {
        const converted = singbox().convertProxy({ ...base, type: 'shadowsocks', method: 'aes-128-gcm', password: 'pass', plugin: 'obfs', plugin_opts: { mode: 'tls', host: 'cdn.example' } });
        expect(converted.plugin).toBe('obfs-local');
        expect(converted.plugin_opts).toBe('obfs=tls;obfs-host=cdn.example');
    });
});

describe('Surge protocol and transport fidelity', () => {
    it('uses the TUIC v5 type for UUID/password credentials', () => {
        const converted = surge().convertProxy({ ...base, type: 'tuic', uuid, password: 'pass', tls: { enabled: true } });
        expect(converted).toContain(' = tuic-v5,');
    });

    it.each(['grpc', 'http', 'httpupgrade'])('marks unsupported VMess %s instead of silently changing the transport', type => {
        const converted = surge().convertProxy({ ...base, type: 'vmess', uuid, transport: { type, service_name: 'service', path: '/' } });
        expect(converted).toMatch(/^# .*Unsupported/);
    });

    it('reads WebSocket Host header names case-insensitively', () => {
        const converted = surge().convertProxy({ ...base, type: 'trojan', password: 'pass', tls: { enabled: true }, transport: { type: 'ws', path: '/ws', headers: { Host: 'cdn.example' } } });
        expect(converted).toContain('ws-headers=Host:cdn.example');
        expect(converted).not.toContain('undefined');
    });

    it('parses a TUIC v5 line without converting it to another protocol version', () => {
        const parsed = convertSurgeProxyToObject(`TUIC = tuic-v5, node.example, 443, uuid=${uuid}, password=pass, sni=sni.example`);
        expect(parsed).toMatchObject({ type: 'tuic', uuid, password: 'pass', tls: { enabled: true, server_name: 'sni.example' } });
    });

    it('parses WebSocket header values rather than treating Host: as part of the host', () => {
        const parsed = convertSurgeProxyToObject('Trojan = trojan, node.example, 443, password=pass, ws=true, ws-path=/ws, ws-headers=Host:cdn.example');
        expect(parsed.transport.headers).toEqual({ Host: 'cdn.example' });
    });

    it('preserves comma-containing credentials when round-tripping Surge', () => {
        const proxy = { ...base, type: 'trojan', password: 'p,a=ss', tls: { enabled: true } };
        const parsed = convertSurgeProxyToObject(surge().convertProxy(proxy));
        expect(parsed.password).toBe(proxy.password);
    });
});
