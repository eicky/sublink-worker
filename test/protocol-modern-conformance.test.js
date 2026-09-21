import { describe, expect, it } from 'vitest';
import { ClashConfigBuilder } from '../src/builders/ClashConfigBuilder.js';
import { SingboxConfigBuilder } from '../src/builders/SingboxConfigBuilder.js';
import { ProxyParser } from '../src/parsers/ProxyParser.js';
import { parseAnytls } from '../src/parsers/protocols/anytlsParser.js';
import { parseHysteria } from '../src/parsers/protocols/hysteriaParser.js';
import { parseHysteria2 } from '../src/parsers/protocols/hysteria2Parser.js';
import { parseTuic } from '../src/parsers/protocols/tuicParser.js';

const UUID = 'd342d11e-d424-4583-b36e-524ab1f0afa4';

describe('Hysteria 1 official URI conformance', () => {
    it('parses the official v1 query fields without conflating them with v2', () => {
        const proxy = parseHysteria(
            'hysteria://example.com:36712?protocol=wechat-video&auth=p%40ss%3Aword&peer=sni.example&insecure=0&upmbps=100&downmbps=200&alpn=hysteria&obfs=xplus&obfsParam=obfs%40pass#HY1%20node'
        );

        expect(proxy).toEqual({
            tag: 'HY1 node',
            type: 'hysteria',
            server: 'example.com',
            server_port: 36712,
            auth_str: 'p@ss:word',
            up_mbps: 100,
            down_mbps: 200,
            protocol: 'wechat-video',
            obfs: 'obfs@pass',
            tls: {
                enabled: true,
                server_name: 'sni.example',
                insecure: false,
                alpn: ['hysteria']
            }
        });
    });

    it('uses the official transport and ALPN defaults and supports bracketed IPv6', () => {
        expect(parseHysteria('hysteria://[2001:db8::4]:443?upmbps=10&downmbps=20#HY1%20IPv6')).toEqual({
            tag: 'HY1 IPv6',
            type: 'hysteria',
            server: '2001:db8::4',
            server_port: 443,
            up_mbps: 10,
            down_mbps: 20,
            protocol: 'udp',
            tls: {
                enabled: true,
                insecure: false,
                alpn: ['hysteria']
            }
        });
    });

    it('keeps Hysteria 1 and Hysteria 2 as distinct internal protocols', () => {
        const v1 = parseHysteria('hysteria://example.com:443?auth=v1-secret&upmbps=10&downmbps=20');
        const v2 = parseHysteria2('hysteria2://v2-secret@example.com:443');

        expect(v1).toMatchObject({ type: 'hysteria', auth_str: 'v1-secret', up_mbps: 10, down_mbps: 20 });
        expect(v1).not.toHaveProperty('password');
        expect(v2).toMatchObject({ type: 'hysteria2', password: 'v2-secret' });
        expect(v2).not.toHaveProperty('auth_str');
    });

    it('routes hysteria, hysteria2 and hy2 to their actual protocol versions', async () => {
        const v1 = await ProxyParser.parse('hysteria://example.com:443?upmbps=10&downmbps=20');
        const v2 = await ProxyParser.parse('hysteria2://secret@example.com:443');
        const v2Alias = await ProxyParser.parse('hy2://secret@example.com:443');

        expect(v1.type).toBe('hysteria');
        expect(v2.type).toBe('hysteria2');
        expect(v2Alias.type).toBe('hysteria2');
    });

    it('emits canonical v1 fields for clients that support the selected transport', () => {
        const proxy = parseHysteria(
            'hysteria://example.com:443?protocol=udp&auth=secret&upmbps=10&downmbps=20&obfs=xplus&obfsParam=cover'
        );
        const singbox = SingboxConfigBuilder.prototype.convertProxy(proxy);
        const clash = ClashConfigBuilder.prototype.convertProxy(proxy);

        expect(singbox).toMatchObject({
            type: 'hysteria',
            auth_str: 'secret',
            up_mbps: 10,
            down_mbps: 20,
            obfs: 'cover',
            tls: { enabled: true, alpn: ['hysteria'] }
        });
        expect(singbox).not.toHaveProperty('protocol');
        expect(clash).toMatchObject({
            type: 'hysteria',
            'auth-str': 'secret',
            up: 10,
            down: 20,
            obfs: 'cover',
            protocol: 'udp',
            alpn: ['hysteria']
        });
    });

    it('preserves v1 transports and rejects targets that cannot represent them', () => {
        const fakeTcp = parseHysteria(
            'hysteria://example.com:443?protocol=faketcp&upmbps=10&downmbps=20'
        );
        const wechatAlias = parseHysteria(
            'hysteria://example.com:443?protocol=wechat&upmbps=10&downmbps=20'
        );

        expect(fakeTcp.protocol).toBe('faketcp');
        expect(ClashConfigBuilder.prototype.convertProxy(fakeTcp).protocol).toBe('faketcp');
        expect(() => SingboxConfigBuilder.prototype.convertProxy(fakeTcp)).toThrow(/transport faketcp/i);
        expect(wechatAlias.protocol).toBe('wechat-video');
    });

    it('rejects missing required fields and unsupported v1 options', () => {
        expect(() => parseHysteria('hysteria://example.com?upmbps=10&downmbps=20')).toThrow(/port/i);
        expect(() => parseHysteria('hysteria://example.com:443?downmbps=20')).toThrow(/upmbps/i);
        expect(() => parseHysteria('hysteria://example.com:443?upmbps=10')).toThrow(/downmbps/i);
        expect(() => parseHysteria('hysteria://example.com:443?upmbps=1.5&downmbps=20')).toThrow(/integer/i);
        expect(() => parseHysteria('hysteria://example.com:443?protocol=tcp&upmbps=10&downmbps=20')).toThrow(/protocol/i);
        expect(() => parseHysteria('hysteria://example.com:443?upmbps=10&downmbps=20&obfs=xplus')).toThrow(/obfsParam/i);
        expect(() => parseHysteria('hysteria://example.com:443?upmbps=10&downmbps=20&insecure=yes')).toThrow(/boolean/i);
        expect(() => parseHysteria2('hysteria://example.com:443?upmbps=10&downmbps=20')).toThrow(/Hysteria 1|scheme/i);
    });
});

describe('Hysteria 2 official URI conformance', () => {
    it('parses encoded userpass auth, IPv6 and native authority port hopping', () => {
        const proxy = parseHysteria2(
            'hy2://alice:p%40ss%3Aword@[2001:db8::1]:443,5000-6000/?sni=front.example&insecure=0&obfs=salamander&obfs-password=obfs%40secret&pinSHA256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef#Node%20A'
        );

        expect(proxy).toMatchObject({
            tag: 'Node A',
            type: 'hysteria2',
            server: '2001:db8::1',
            server_port: 443,
            password: 'alice:p@ss:word',
            ports: '443,5000-6000',
            obfs: {
                type: 'salamander',
                password: 'obfs@secret'
            },
            tls: {
                enabled: true,
                server_name: 'front.example',
                insecure: false,
                certificate_sha256: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
            }
        });
    });

    it('preserves whole-certificate pinning only for targets with equivalent semantics', () => {
        const proxy = parseHysteria2(
            'hysteria2://secret@example.com:443?pinSHA256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef#Pinned'
        );

        expect(ClashConfigBuilder.prototype.convertProxy(proxy).fingerprint).toBe(
            '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
        );
        expect(() => SingboxConfigBuilder.prototype.convertProxy(proxy)).toThrow(/pinning|fingerprint/i);
    });

    it('maps official ECH data into each target client format', () => {
        const proxy = parseHysteria2('hysteria2://secret@example.com:443?ech=AAEC#ECH');
        const clash = ClashConfigBuilder.prototype.convertProxy(proxy);
        const singbox = SingboxConfigBuilder.prototype.convertProxy(proxy);
        const singboxPem = Array.isArray(singbox.tls.ech.config)
            ? singbox.tls.ech.config.join('\n')
            : singbox.tls.ech.config;

        expect(clash['ech-opts']).toEqual({ enable: true, config: 'AAEC' });
        expect(singboxPem).toBe('-----BEGIN ECH CONFIGS-----\nAAEC\n-----END ECH CONFIGS-----');
        expect(singbox.tls.ech).not.toHaveProperty('format');
    });

    it('uses port 443 and empty auth when both optional URI components are absent', () => {
        const proxy = parseHysteria2('hysteria2://example.com/#No%20auth');

        expect(proxy).toMatchObject({
            tag: 'No auth',
            server: 'example.com',
            server_port: 443,
            password: '',
            tls: { enabled: true, insecure: false }
        });
    });

    it('keeps supported client port-hopping aliases but validates their values', () => {
        const proxy = parseHysteria2(
            'hysteria2://secret@example.com:443?mport=20000-30000%2C40000&hop_interval=15&hop-interval-max=30#Hop'
        );

        expect(proxy.ports).toBe('20000-30000,40000');
        expect(proxy.hop_interval).toBe(15);
        expect(proxy.hop_interval_max).toBe(30);
        expect(() => parseHysteria2('hysteria2://secret@example.com:443?ports=0-100')).toThrow(/port/i);
        expect(() => parseHysteria2('hysteria2://secret@example.com:443?ports=500-100')).toThrow(/port/i);
        expect(() => parseHysteria2('hysteria2://secret@example.com:443?hop-interval=15')).toThrow(/port hopping/i);
    });

    it('does not reinterpret Hysteria 1 fields as Hysteria 2 fields', () => {
        const proxy = parseHysteria2(
            'hysteria2://secret@example.com:443?auth=v1-auth&alpn=hysteria&upmbps=100&downmbps=200'
        );

        expect(proxy.password).toBe('secret');
        expect(proxy.tls.server_name).toBeUndefined();
        expect(proxy.tls.alpn).toBeUndefined();
        expect(proxy).not.toHaveProperty('auth');
        expect(proxy).not.toHaveProperty('up');
        expect(proxy).not.toHaveProperty('down');
        expect(proxy).not.toHaveProperty('up_mbps');
        expect(proxy).not.toHaveProperty('down_mbps');
        expect(() => parseHysteria2('hysteria2://example.com:443?auth=v1-auth')).toThrow(/Hysteria 1 auth/i);
        expect(() => parseHysteria2('hysteria2://secret@example.com:443?peer=v1.example')).toThrow(/Hysteria 1 peer/i);
    });

    it('rejects Hysteria 1 links instead of silently treating them as v2', () => {
        expect(() => parseHysteria2('hysteria://example.com:443?auth=secret&upmbps=10&downmbps=50')).toThrow(/Hysteria 1|scheme/i);
    });

    it('rejects malformed auth and incomplete obfs while preserving official ECH data', () => {
        expect(() => parseHysteria2('hysteria2://bad%ZZ@example.com:443')).toThrow();
        expect(() => parseHysteria2('hysteria2://bad@auth@example.com:443')).toThrow(/percent-encode/i);
        expect(() => parseHysteria2('hysteria2://secret@example.com:443?obfs-password=secret')).toThrow(/obfs/i);
        expect(() => parseHysteria2('hysteria2://secret@example.com:443?obfs=unknown&obfs-password=secret')).toThrow(/obfs/i);
        expect(() => parseHysteria2('hysteria2://secret@example.com:443?security=none')).toThrow(/TLS mode/i);
        expect(parseHysteria2('hysteria2://secret@example.com:443?ech=AAEC').tls.ech).toEqual({
            enabled: true,
            config: ['-----BEGIN ECH CONFIGS-----', 'AAEC', '-----END ECH CONFIGS-----']
        });
        expect(() => parseHysteria2('hysteria2://secret@example.com:443?ech=not_base64!')).toThrow(/Base64/i);
    });

    it('normalizes Hysteria 2 fields for sing-box and Mihomo', () => {
        const proxy = parseHysteria2(
            'hysteria2://secret@example.com:443,5000-6000?obfs=gecko&obfs-password=secret&obfs-min-packet-size=512&obfs-max-packet-size=1200&hop-interval=15&hop-interval-max=30#Gecko'
        );
        const singbox = SingboxConfigBuilder.prototype.convertProxy.call({ singboxVersion: '1.14' }, proxy);
        const clash = ClashConfigBuilder.prototype.convertProxy(proxy);

        expect(singbox).toMatchObject({
            server_ports: ['443:443', '5000:6000'],
            hop_interval: '15s',
            hop_interval_max: '30s',
            obfs: {
                type: 'gecko',
                password: 'secret',
                min_packet_size: 512,
                max_packet_size: 1200
            }
        });
        expect(singbox).not.toHaveProperty('server_port');
        expect(clash).toMatchObject({
            ports: '443,5000-6000',
            'hop-interval': '15-30',
            obfs: 'gecko',
            'obfs-password': 'secret',
            'obfs-min-packet-size': 512,
            'obfs-max-packet-size': 1200
        });
    });
});

describe('TUIC v5 project URI profile', () => {
    it('decodes UUID/password components once and preserves v5 client options', () => {
        const proxy = parseTuic(
            `tuic://${UUID}:p%3Aa%40ss%2520@[2001:db8::2]:10443?congestion_control=bbr&udp_relay_mode=quic&zero_rtt_handshake=1&heartbeat=3s&sni=tuic.example&allow_insecure=0&alpn=h3%2Chq-29&disable_sni=0#TUIC%20v5`
        );

        expect(proxy).toEqual({
            tag: 'TUIC v5',
            type: 'tuic',
            server: '2001:db8::2',
            server_port: 10443,
            uuid: UUID,
            password: 'p:a@ss%20',
            congestion_control: 'bbr',
            udp_relay_mode: 'quic',
            zero_rtt_handshake: true,
            heartbeat: '3s',
            tls: {
                enabled: true,
                server_name: 'tuic.example',
                alpn: ['h3', 'hq-29'],
                insecure: false,
                disable_sni: false
            }
        });
    });

    it('uses stable v5 defaults where sing-box and Mihomo otherwise diverge', () => {
        const proxy = parseTuic(`tuic://${UUID}:secret@example.com:443`);

        expect(proxy.tag).toBe('example.com:443');
        expect(proxy.congestion_control).toBe('cubic');
        expect(proxy.udp_relay_mode).toBe('native');
        expect(proxy.tls).toEqual({ enabled: true, insecure: false, alpn: [] });
        expect(proxy).not.toHaveProperty('heartbeat');
    });

    it('supports the Mihomo-style aliases without leaking them into the internal object', () => {
        const proxy = parseTuic(
            `tuic://${UUID}:secret@example.com:443?congestion-controller=new_reno&udp-relay-mode=native&reduce-rtt=false&heartbeat-interval=12500`
        );

        expect(proxy).toMatchObject({
            congestion_control: 'new_reno',
            udp_relay_mode: 'native',
            zero_rtt_handshake: false,
            heartbeat: '12500ms'
        });
        expect(proxy).not.toHaveProperty('reduce_rtt');
        expect(proxy).not.toHaveProperty('zero_rtt');
    });

    it('rejects v4-shaped credentials and invalid v5 options', () => {
        expect(() => parseTuic('tuic://legacy-token@example.com:443')).toThrow(/v4|UUID.*password|credentials/i);
        expect(() => parseTuic(`tuic://${UUID}:secret@example.com`)).toThrow(/port/i);
        expect(() => parseTuic('tuic://not-a-uuid:secret@example.com:443')).toThrow(/UUID/i);
        expect(() => parseTuic(`tuic://${UUID}:p:a@example.com:443`)).toThrow(/percent-encode/i);
        expect(() => parseTuic(`tuic://${UUID}:secret@example.com:443?congestion_control=reno`)).toThrow(/congestion/i);
        expect(() => parseTuic(`tuic://${UUID}:secret@example.com:443?congestion_control=`)).toThrow(/congestion/i);
        expect(() => parseTuic(`tuic://${UUID}:secret@example.com:443?udp_relay_mode=datagram`)).toThrow(/UDP relay/i);
        expect(() => parseTuic(`tuic://${UUID}:secret@example.com:443?heartbeat=1us`)).toThrow(/milliseconds/i);
        expect(() => parseTuic(`tuic://${UUID}:secret@example.com:443?security=none`)).toThrow(/TLS mode/i);
        expect(() => parseTuic(`tuic://${UUID}:secret@example.com:443?allow_insecure=maybe`)).toThrow(/boolean|allow_insecure/i);
    });

    it('does not weaken verification when mapping disable_sni to Mihomo', () => {
        const verified = parseTuic(`tuic://${UUID}:secret@example.com:443?disable_sni=1`);
        const explicitlyInsecure = parseTuic(`tuic://${UUID}:secret@example.com:443?disable_sni=1&allow_insecure=1`);

        expect(SingboxConfigBuilder.prototype.convertProxy(verified).tls.disable_sni).toBe(true);
        expect(() => ClashConfigBuilder.prototype.convertProxy(verified)).toThrow(/disable.*SNI|certificate verification/i);
        expect(ClashConfigBuilder.prototype.convertProxy(explicitlyInsecure)).toMatchObject({
            'disable-sni': true,
            'skip-cert-verify': true
        });
    });

    it('maps canonical TUIC options to both target clients', () => {
        const proxy = parseTuic(
            `tuic://${UUID}:secret@example.com:443?congestion_control=cubic&udp_relay_mode=quic&zero_rtt_handshake=1&heartbeat=3s&sni=tuic.example`
        );
        const singbox = SingboxConfigBuilder.prototype.convertProxy(proxy);
        const clash = ClashConfigBuilder.prototype.convertProxy(proxy);

        expect(singbox).toMatchObject({
            congestion_control: 'cubic',
            udp_relay_mode: 'quic',
            zero_rtt_handshake: true,
            heartbeat: '3s'
        });
        expect(clash).toMatchObject({
            'congestion-controller': 'cubic',
            'udp-relay-mode': 'quic',
            'reduce-rtt': true,
            'heartbeat-interval': 3000
        });
    });
});

describe('AnyTLS official URI conformance', () => {
    it('decodes the password once, supports IPv6 and keeps explicit false values', () => {
        const proxy = parseAnytls(
            'anytls://p%40ss%3Aword%2520@[2001:db8::3]:8443/?sni=any.example&insecure=0&udp=false#AnyTLS%20IPv6'
        );

        expect(proxy).toMatchObject({
            tag: 'AnyTLS IPv6',
            type: 'anytls',
            server: '2001:db8::3',
            server_port: 8443,
            password: 'p@ss:word%20',
            udp: false,
            tls: {
                enabled: true,
                server_name: 'any.example',
                insecure: false
            }
        });
    });

    it('uses the official default port and a stable tag without a fragment', () => {
        expect(parseAnytls('anytls://secret@example.com/')).toEqual({
            tag: 'AnyTLS example.com:443',
            type: 'anytls',
            server: 'example.com',
            server_port: 443,
            password: 'secret',
            tls: {
                enabled: true,
                insecure: false
            }
        });
    });

    it('keeps the official optional auth component optional', () => {
        expect(parseAnytls('anytls://example.com:443#No%20auth')).toMatchObject({
            tag: 'No auth',
            server: 'example.com',
            server_port: 443,
            password: ''
        });
    });

    it('keeps documented client extensions in target-compatible units', () => {
        const proxy = parseAnytls(
            'anytls://secret@example.com:443?alpn=h2%2Chttp%2F1.1&fp=chrome&fingerprint=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef&idle-session-check-interval=30&idle_session_timeout=60&min-idle-session=2'
        );

        expect(proxy).toMatchObject({
            idle_session_check_interval: 30,
            idle_session_timeout: 60,
            min_idle_session: 2,
            tls: {
                alpn: ['h2', 'http/1.1'],
                utls: { enabled: true, fingerprint: 'chrome' },
                certificate_sha256: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
            }
        });
    });

    it('rejects malformed URI values instead of manufacturing a usable-looking node', () => {
        expect(() => parseAnytls('anytls://bad%ZZ@example.com:443')).toThrow();
        expect(() => parseAnytls('anytls://raw:colon@example.com:443')).toThrow(/percent-encode/i);
        expect(() => parseAnytls('anytls://secret@example.com:443?sni=%ZZ')).toThrow(/percent|encoding|URI/i);
        expect(() => parseAnytls('anytls://secret@example.com:443?insecure=yes')).toThrow(/boolean|insecure/i);
        expect(() => parseAnytls('anytls://secret@example.com:443?fingerprint=chrome')).toThrow(/SHA-256/i);
        expect(() => parseAnytls('anytls://secret@example.com:443?insecure=0&insecure=1')).toThrow(/duplicate/i);
        expect(() => parseAnytls('anytls://secret@example.com:443?security=reality')).toThrow(/TLS mode/i);
        expect(() => parseAnytls('anytls://secret@example.com:443?ech=AAEC')).toThrow(/ECH/i);
        expect(() => parseAnytls('anytls://secret@example.com:70000')).toThrow(/port|invalid/i);
        expect(() => parseAnytls('anytls://secret@example.com:443?idle-session-timeout=-1')).toThrow(/idle-session-timeout/i);
        expect(() => parseAnytls('anytls://secret@example.com:443?idle-session-timeout=1.5')).toThrow(/idle-session-timeout/i);
        expect(() => parseAnytls('anytls://secret@example.com:443?min-idle-session=1.5')).toThrow(/min-idle-session/i);
        expect(() => parseAnytls('anytls://secret@example.com:443?max-idle-session=5')).toThrow(/max.*not supported/i);
    });
});
