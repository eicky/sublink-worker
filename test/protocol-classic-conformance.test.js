import { describe, expect, it } from 'vitest';
import { parseShadowsocks } from '../src/parsers/protocols/shadowsocksParser.js';
import { parseVmess } from '../src/parsers/protocols/vmessParser.js';

function createVmessUrl(config, fragment = '') {
    const payload = Buffer.from(JSON.stringify(config), 'utf8').toString('base64');
    return `vmess://${payload}${fragment ? `#${encodeURIComponent(fragment)}` : ''}`;
}

describe('legacy VMess TLS defaults', () => {
    it('matches v2rayN by using the transport Host when the JSON SNI is omitted', () => {
        const proxy = parseVmess(createVmessUrl({ v: '2', add: '203.0.113.1', port: '443', id: '12345678-1234-4234-8234-123456789abc', net: 'ws', host: 'cdn.example', path: '/ws', tls: 'tls' }));
        expect(proxy.tls.server_name).toBe('cdn.example');
    });
});

describe('Shadowsocks SIP002 conformance', () => {
    it('decodes unpadded Base64URL UTF-8 credentials with an IPv6 server and fragment', () => {
        const result = parseShadowsocks(
            'ss://YWVzLTI1Ni1nY2065a-G56CBOnBhc3MrLz8@[2001:db8::1]:8388#%E8%8A%82%E7%82%B9'
        );

        expect(result).toMatchObject({
            tag: '节点',
            type: 'shadowsocks',
            server: '2001:db8::1',
            server_port: 8388,
            method: 'aes-256-gcm',
            password: '密码:pass+/?'
        });
    });

    it('parses percent-encoded plain AEAD-2022 userinfo without Base64URL wrapping', () => {
        const result = parseShadowsocks(
            'ss://2022-blake3-aes-128-gcm:AAAAAAAAAAAAAAAAAAAAAA%3D%3D@example.com:443#AEAD-2022'
        );

        expect(result).toMatchObject({
            tag: 'AEAD-2022',
            server: 'example.com',
            server_port: 443,
            method: '2022-blake3-aes-128-gcm',
            password: 'AAAAAAAAAAAAAAAAAAAAAA=='
        });
    });

    it('keeps delimiters in legacy passwords and parses a bracketed IPv6 server', () => {
        const result = parseShadowsocks(
            'ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTp0ZXN0LyFAIzpAWzIwMDE6ZGI4OjoyXTo4Mzg4#Legacy'
        );

        expect(result).toMatchObject({
            tag: 'Legacy',
            server: '2001:db8::2',
            server_port: 8388,
            method: 'chacha20-ietf-poly1305',
            password: 'test/!@#:'
        });
    });

    it('parses plain percent-encoded userinfo and SIP003 escaped plugin options', () => {
        const result = parseShadowsocks(
            'ss://aes-128-gcm:p%3Ass%40word@example.com:8388/?plugin=example-plugin%3Bkey%3Da%5C%3Bb%5C%3Dc%5C%5Cd%5C%3Ae%3Bflag#Plugin'
        );

        expect(result).toMatchObject({
            method: 'aes-128-gcm',
            password: 'p:ss@word',
            plugin: 'example-plugin',
            plugin_opts: {
                key: 'a;b=c\\d:e',
                flag: true
            }
        });
    });

    it('keeps SIP003 plugin names and option keys in protocol form', () => {
        const result = parseShadowsocks(
            'ss://YWVzLTEyOC1nY206cGFzcw@example.com:8388/?plugin=simple-obfs%3Bobfs%3Dhttp%3Bobfs-host%3Dcdn.example#Plugin'
        );

        expect(result).toMatchObject({
            plugin: 'simple-obfs',
            plugin_opts: {
                obfs: 'http',
                'obfs-host': 'cdn.example'
            }
        });
    });

    it('accepts the optional authority slash in SIP002 plugin links', () => {
        const result = parseShadowsocks('ss://YWVzLTEyOC1nY206cGFzcw@example.com:8388?plugin=simple-obfs%3Bobfs%3Dhttp#Plugin');
        expect(result).toMatchObject({ plugin: 'simple-obfs', plugin_opts: { obfs: 'http' } });
    });

    it('gives an unnamed SIP002 link a usable derived tag', () => {
        expect(parseShadowsocks('ss://YWVzLTEyOC1nY206cGFzcw@example.com:8388').tag).toBe('example.com:8388');
    });

    it.each([
        'ss://YWVzLTEyOC1nY206cGFzcw@example.com:8388/?plugin=#Plugin',
        'ss://bad%20method:pass@example.com:8388#Invalid-Method',
        'ss://MjAyMi1ibGFrZTMtYWVzLTEyOC1nY206QUFBQUFBQUFBQUFBQUFBQUFBQUFBQT09@example.com:443#Invalid',
        'ss://2022-blake3-aes-128-gcm:AA%3D%3D@example.com:443#Invalid-Key',
        'ss://YWVzLTEyOC1nY206cGFzcw@example.com#No-Port'
    ])('reports a malformed SS link instead of dropping it: %s', uri => {
        expect(() => parseShadowsocks(uri)).toThrow();
    });
});

describe('Xray VMessAEAD share-link proposal', () => {
    it.each(['http', 'h2'])('keeps HTTP/2 host and path for the %s transport', type => {
        const proxy = parseVmess(`vmess://12345678-1234-4234-8234-123456789abc@node.example:443?security=tls&type=${type}&host=cdn.example&path=%2Fh2&sni=sni.example`);
        expect(proxy.transport).toEqual({ type: 'http', host: ['cdn.example'], path: '/h2' });
        expect(proxy.tls.server_name).toBe('sni.example');
    });

    it('parses an authority-style VMess AEAD link', () => {
        const result = parseVmess(
            'vmess://12345678-1234-4234-8234-123456789abc@vmess.example:443?encryption=aes-128-gcm'
        );

        expect(result).toMatchObject({
            tag: 'vmess.example:443',
            type: 'vmess',
            server: 'vmess.example',
            server_port: 443,
            uuid: '12345678-1234-4234-8234-123456789abc',
            alter_id: 0,
            security: 'aes-128-gcm',
            tcp_fast_open: false
        });
        expect(result.transport).toBeUndefined();
        expect(result.tls).toBeUndefined();
    });

    it('maps proposal TLS and WebSocket fields without using HTTP Host as SNI', () => {
        const result = parseVmess(
            'vmess://12345678-1234-4234-8234-123456789abc@[2001:db8::20]:443?type=ws&security=tls&host=cdn.example&path=%2Fws%3Fed%3D2048%26x%3D1&alpn=h2%2Chttp%2F1.1&fp=firefox#%E8%8A%82%E7%82%B9'
        );

        expect(result).toMatchObject({
            tag: '节点',
            server: '2001:db8::20',
            server_port: 443,
            transport: {
                type: 'ws',
                path: '/ws?x=1',
                headers: { Host: 'cdn.example' },
                max_early_data: 2048,
                early_data_header_name: 'Sec-WebSocket-Protocol'
            },
            tls: {
                enabled: true,
                server_name: '2001:db8::20',
                insecure: false,
                alpn: ['h2', 'http/1.1'],
                utls: { enabled: true, fingerprint: 'firefox' }
            }
        });
    });

    it('preserves a proposal certificate SHA-256 pin', () => {
        const fingerprint = Array(32).fill('AA').join(':');
        const result = parseVmess(
            `vmess://12345678-1234-4234-8234-123456789abc@vmess.example:443?security=tls&pcs=${encodeURIComponent(` ${fingerprint} `)}`
        );

        expect(result.tls.certificate_sha256).toBe('aa'.repeat(32));
        expect(parseVmess(
            'vmess://12345678-1234-4234-8234-123456789abc@vmess.example:443?security=tls&pcs=%20'
        ).tls.certificate_sha256).toBeUndefined();
    });

    it('maps proposal REALITY and gRPC fields', () => {
        const result = parseVmess(
            'vmess://12345678-1234-4234-8234-123456789abc@reality.example:443?type=grpc&serviceName=service.Name&mode=multi&authority=authority.example&security=reality&pbk=public-key&sid=abcd'
        );

        expect(result).toMatchObject({
            transport: {
                type: 'grpc',
                service_name: 'service.Name',
                mode: 'multi',
                authority: 'authority.example'
            },
            tls: {
                enabled: true,
                server_name: 'reality.example',
                utls: { enabled: true, fingerprint: 'chrome' },
                reality: { enabled: true, public_key: 'public-key', short_id: 'abcd' }
            }
        });
    });

    it('rejects a proposal gRPC mode outside the defined values', () => {
        const url = 'vmess://12345678-1234-4234-8234-123456789abc@grpc.example:443?type=grpc&mode=invalid';

        expect(() => parseVmess(url)).toThrow(/mode/i);
    });

    it.each(['zero', ''])('rejects proposal encryption=%j', encryption => {
        const url = `vmess://12345678-1234-4234-8234-123456789abc@vmess.example:443?encryption=${encryption}`;

        expect(() => parseVmess(url)).toThrow(/encryption|security/i);
    });

    it.each(['aid=1', 'insecure=1', 'Type=ws'])(
        'rejects query fields outside the proposal: %s',
        query => {
            const url = `vmess://12345678-1234-4234-8234-123456789abc@vmess.example:443?${query}`;

            expect(() => parseVmess(url)).toThrow(/query|parameter|field/i);
        }
    );

    it.each([
        'sni=tls.example',
        `pcs=${'aa'.repeat(32)}`,
        'pbk=public-key'
    ])('rejects TLS-only proposal fields without TLS: %s', field => {
        const url = `vmess://12345678-1234-4234-8234-123456789abc@vmess.example:443?security=none&${field}`;

        expect(() => parseVmess(url)).toThrow(/TLS|security|REALITY/i);
    });

    it.each([
        'security=tls&pbk=public-key',
        'security=tls&sid=abcd',
        `security=reality&pbk=public-key&pcs=${'aa'.repeat(32)}`
    ])('rejects proposal TLS fields in the wrong security mode: %s', query => {
        const url = `vmess://12345678-1234-4234-8234-123456789abc@vmess.example:443?${query}`;

        expect(() => parseVmess(url)).toThrow(/TLS|security|REALITY/i);
    });

    it.each([
        'security=tls&sni=',
        'security=tls&fp=',
        'security=tls&alpn=',
        'type=ws&path=',
        'type=grpc&serviceName='
    ])('rejects proposal fields that are present but empty: %s', query => {
        const url = `vmess://12345678-1234-4234-8234-123456789abc@vmess.example:443?${query}`;

        expect(() => parseVmess(url)).toThrow(/empty|field|parameter/i);
    });

    it.each([
        'type=tcp&host=cdn.example',
        'type=ws&serviceName=service.Name',
        'type=grpc&path=%2Fgrpc',
        'type=ws&mode=multi',
        'type=grpc&extra=%7B%7D'
    ])('rejects transport fields outside their proposal transport: %s', query => {
        const url = `vmess://12345678-1234-4234-8234-123456789abc@vmess.example:443?${query}`;

        expect(() => parseVmess(url)).toThrow(/transport|field|parameter/i);
    });

    it('maps proposal XHTTP mode and extra JSON', () => {
        const result = parseVmess(
            'vmess://12345678-1234-4234-8234-123456789abc@xhttp.example:443?type=xhttp&host=cdn.example&path=%2Fxhttp&mode=packet-up&extra=%7B%22scMaxEachPostBytes%22%3A1000000%7D'
        );

        expect(result.transport).toEqual({
            type: 'xhttp',
            host: 'cdn.example',
            path: '/xhttp',
            mode: 'packet-up',
            extra: { scMaxEachPostBytes: 1000000 }
        });
    });

    it('preserves proposal ECH data in canonical TLS', () => {
        const result = parseVmess(
            'vmess://12345678-1234-4234-8234-123456789abc@vmess.example:443?security=tls&ech=AAEC'
        );

        expect(result.tls.ech).toEqual({
            enabled: true,
            config: ['-----BEGIN ECH CONFIGS-----', 'AAEC', '-----END ECH CONFIGS-----']
        });
    });

    it('validates non-empty proposal ECH data while allowing its documented empty value', () => {
        const empty = parseVmess(
            'vmess://12345678-1234-4234-8234-123456789abc@vmess.example:443?security=tls&ech='
        );

        expect(empty.tls.ech).toBeUndefined();
        expect(() => parseVmess(
            'vmess://12345678-1234-4234-8234-123456789abc@vmess.example:443?security=tls&ech=not_base64!'
        )).toThrow(/Base64|ECH/i);
    });

    it.each([
        'type=kcp&mtu=1350',
        'type=tcp&fm=%7B%7D',
        'security=tls&vcn=verify.example',
        'security=reality&pbk=public-key&pqv=post-quantum-key'
    ])('rejects proposal options that the canonical model cannot preserve: %s', query => {
        const url = `vmess://12345678-1234-4234-8234-123456789abc@vmess.example:443?${query}`;

        expect(() => parseVmess(url)).toThrow(/unsupported|cannot|transport|option/i);
    });
});

describe('v2rayN VMess JSON share-link compatibility', () => {
    it('matches v2rayN case-insensitive JSON property handling', () => {
        const result = parseVmess(createVmessUrl({
            V: '2',
            PS: 'Uppercase fields',
            ADD: 'vmess.example',
            PORT: '443',
            ID: '12345678-1234-4234-8234-123456789abc',
            AID: '0',
            NET: 'tcp',
            TYPE: 'none'
        }));

        expect(result).toMatchObject({
            tag: 'Uppercase fields',
            server: 'vmess.example',
            server_port: 443,
            alter_id: 0
        });
    });

    it('accepts a case-insensitive URI scheme', () => {
        const url = createVmessUrl({
            v: 2,
            ps: 'Uppercase scheme',
            add: 'vmess.example',
            port: '443',
            id: '12345678-1234-4234-8234-123456789abc',
            aid: 0,
            net: 'tcp',
            type: 'none'
        }).replace('vmess://', 'VMESS://');

        expect(parseVmess(url).tag).toBe('Uppercase scheme');
    });

    it('keeps the existing fragment tag override compatibility', () => {
        const result = parseVmess(createVmessUrl({
            v: 2,
            ps: 'JSON tag',
            add: 'vmess.example',
            port: '443',
            id: '12345678-1234-4234-8234-123456789abc',
            aid: 0,
            net: 'tcp',
            type: 'none'
        }, 'Override @ #1'));

        expect(result.tag).toBe('Override @ #1');
    });

    it('decodes unpadded Base64URL UTF-8 JSON and maps documented TLS fields', () => {
        const result = parseVmess(
            'vmess://eyJ2IjoyLCJwcyI6IuiKgueCucK-IiwiYWRkIjoidm1lc3MuZXhhbXBsZSIsInBvcnQiOiI0NDMiLCJpZCI6IjEyMzQ1Njc4LTEyMzQtMTIzNC0xMjM0LTEyMzQ1Njc4OWFiYyIsImFpZCI6MCwic2N5IjoiYXV0byIsIm5ldCI6IndzIiwidHlwZSI6Im5vbmUiLCJob3N0IjoiY2RuLmV4YW1wbGUiLCJwYXRoIjoiL-i3r-W-hD94PTEiLCJ0bHMiOiJ0bHMiLCJzbmkiOiJzbmkuZXhhbXBsZSIsImFscG4iOiJoMixodHRwLzEuMSIsImZwIjoiY2hyb21lIiwiaW5zZWN1cmUiOiIwIn0'
        );

        expect(result).toMatchObject({
            tag: '节点¾',
            type: 'vmess',
            server: 'vmess.example',
            server_port: 443,
            uuid: '12345678-1234-1234-1234-123456789abc',
            alter_id: 0,
            security: 'auto',
            transport: {
                type: 'ws',
                path: '/路径?x=1',
                headers: { Host: 'cdn.example' }
            },
            tls: {
                enabled: true,
                server_name: 'sni.example',
                insecure: false,
                alpn: ['h2', 'http/1.1'],
                utls: {
                    enabled: true,
                    fingerprint: 'chrome'
                }
            }
        });
    });

    it('accepts documented numeric fields and splits HTTP camouflage hosts', () => {
        const result = parseVmess(createVmessUrl({
            v: '2',
            ps: 'HTTP node',
            add: '2001:db8::10',
            port: 8080,
            id: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
            aid: '1',
            scy: 'chacha20-poly1305',
            net: 'tcp',
            type: 'http',
            host: 'one.example,two.example',
            path: '/camouflage',
            tls: ''
        }));

        expect(result).toMatchObject({
            tag: 'HTTP node',
            server: '2001:db8::10',
            server_port: 8080,
            alter_id: 1,
            security: 'chacha20-poly1305',
            transport: {
                type: 'http-obfs',
                method: 'GET',
                path: ['/camouflage'],
                headers: {
                    Host: ['one.example', 'two.example']
                }
            }
        });
        expect(result.tls).toBeUndefined();
    });

    it('normalizes the h2 alias to the canonical HTTP transport', () => {
        const result = parseVmess(createVmessUrl({
            v: 2,
            ps: 'H2 node',
            add: 'h2.example',
            port: '443',
            id: '22222222-3333-4444-8555-666666666666',
            aid: 0,
            net: 'h2',
            type: 'none',
            host: 'cdn.example',
            path: '/h2',
            tls: 'tls',
            sni: 'h2.example'
        }));

        expect(result.transport).toEqual({
            type: 'http',
            host: ['cdn.example'],
            path: '/h2'
        });
    });

    it('maps gRPC path and Host to service name and authority', () => {
        const result = parseVmess(createVmessUrl({
            v: 2,
            ps: 'gRPC node',
            add: 'grpc.example',
            port: '443',
            id: '11111111-2222-4333-8444-555555555555',
            aid: 0,
            net: 'grpc',
            type: 'gun',
            host: 'authority.example',
            path: 'service.Name',
            tls: 'tls',
            sni: 'grpc.example'
        }));

        expect(result.transport).toEqual({
            type: 'grpc',
            service_name: 'service.Name',
            authority: 'authority.example'
        });
    });

    it('does not turn the generic gRPC type=none into a transport mode', () => {
        const result = parseVmess(createVmessUrl({
            v: 2,
            ps: 'gRPC default mode',
            add: 'grpc.example',
            port: '443',
            id: '77777777-6666-4555-8444-333333333333',
            aid: 0,
            net: 'grpc',
            type: 'none',
            path: 'service.Name'
        }));

        expect(result.transport).toEqual({
            type: 'grpc',
            service_name: 'service.Name'
        });
    });

    it('does not turn TLS SNI into a WebSocket Host header', () => {
        const result = parseVmess(createVmessUrl({
            v: 2,
            ps: 'WS without Host',
            add: 'ws.example',
            port: '443',
            id: '99999999-8888-4777-8666-555555555555',
            aid: 0,
            net: 'ws',
            type: 'none',
            host: '',
            path: '/ws',
            tls: 'tls',
            sni: 'sni.example'
        }));

        expect(result.transport).toEqual({
            type: 'ws',
            path: '/ws'
        });
        expect(result.tls.server_name).toBe('sni.example');
    });

    it('rejects a port that is not an exact integer', () => {
        const url = createVmessUrl({
            v: 2,
            ps: 'Invalid port',
            add: 'vmess.example',
            port: '443junk',
            id: '12345678-1234-4234-8234-123456789abc',
            aid: 0,
            net: 'tcp',
            type: 'none'
        });

        expect(() => parseVmess(url)).toThrow(/port/i);
    });

    it('rejects an alterId outside the VMess uint16 range', () => {
        const url = createVmessUrl({
            v: 2,
            ps: 'Invalid alterId',
            add: 'vmess.example',
            port: '443',
            id: '12345678-1234-4234-8234-123456789abc',
            aid: '65536',
            net: 'tcp',
            type: 'none'
        });

        expect(() => parseVmess(url)).toThrow(/alterId/i);
    });

    it('rejects an invalid server address', () => {
        const url = createVmessUrl({
            v: 2,
            ps: 'Invalid server',
            add: 'bad host',
            port: '443',
            id: '12345678-1234-4234-8234-123456789abc',
            aid: 0,
            net: 'tcp',
            type: 'none'
        });

        expect(() => parseVmess(url)).toThrow(/server|address/i);
    });

    it('rejects a VMess user ID that is not a UUID', () => {
        const url = createVmessUrl({
            v: 2,
            ps: 'Invalid ID',
            add: 'vmess.example',
            port: '443',
            id: 'not-a-uuid',
            aid: 0,
            net: 'tcp',
            type: 'none'
        });

        expect(() => parseVmess(url)).toThrow(/UUID/i);
    });

    it('maps the current v2rayN HTTPUpgrade fields', () => {
        const result = parseVmess(createVmessUrl({
            v: 2,
            ps: 'HTTPUpgrade node',
            add: 'upgrade.example',
            port: '443',
            id: '12345678-1234-4234-8234-123456789abc',
            aid: 0,
            net: 'httpupgrade',
            type: 'none',
            host: 'cdn.example',
            path: '/upgrade',
            tls: 'tls',
            sni: 'upgrade.example'
        }));

        expect(result.transport).toEqual({
            type: 'httpupgrade',
            host: 'cdn.example',
            path: '/upgrade'
        });
    });

    it('maps the current v2rayN XHTTP fields without losing its mode', () => {
        const result = parseVmess(createVmessUrl({
            v: 2,
            ps: 'XHTTP node',
            add: 'xhttp.example',
            port: '443',
            id: '12345678-1234-4234-8234-123456789abc',
            aid: 0,
            net: 'xhttp',
            type: 'packet-up',
            host: 'cdn.example',
            path: '/xhttp',
            tls: 'tls',
            sni: 'xhttp.example'
        }));

        expect(result.transport).toEqual({
            type: 'xhttp',
            host: 'cdn.example',
            path: '/xhttp',
            mode: 'packet-up'
        });
    });

    it('rejects a documented transport that this output model cannot represent', () => {
        const url = createVmessUrl({
            v: 2,
            ps: 'Unsupported KCP',
            add: 'vmess.example',
            port: '443',
            id: '12345678-1234-4234-8234-123456789abc',
            aid: 0,
            net: 'kcp',
            type: 'srtp',
            path: 'seed'
        });

        expect(() => parseVmess(url)).toThrow(/transport|network/i);
    });

    it('rejects a TCP camouflage type that cannot be represented', () => {
        const url = createVmessUrl({
            v: 2,
            ps: 'Invalid TCP type',
            add: 'vmess.example',
            port: '443',
            id: '12345678-1234-4234-8234-123456789abc',
            aid: 0,
            net: 'tcp',
            type: 'srtp'
        });

        expect(() => parseVmess(url)).toThrow(/type|transport/i);
    });

    it('rejects an unsupported gRPC mode instead of dropping it', () => {
        const url = createVmessUrl({
            v: 2,
            ps: 'Invalid gRPC mode',
            add: 'grpc.example',
            port: '443',
            id: '12345678-1234-4234-8234-123456789abc',
            aid: 0,
            net: 'grpc',
            type: 'invalid-mode',
            path: 'service.Name'
        });

        expect(() => parseVmess(url)).toThrow(/mode|type/i);
    });

    it('rejects non-string documented transport fields', () => {
        const url = createVmessUrl({
            v: 2,
            ps: 'Invalid Host',
            add: 'vmess.example',
            port: '443',
            id: '12345678-1234-4234-8234-123456789abc',
            aid: 0,
            net: 'ws',
            type: 'none',
            host: ['cdn.example'],
            path: '/ws'
        });

        expect(() => parseVmess(url)).toThrow(/host/i);
    });

    it('rejects malformed compatibility HTTP headers', () => {
        const url = createVmessUrl({
            v: 2,
            ps: 'Invalid headers',
            add: 'vmess.example',
            port: '443',
            id: '12345678-1234-4234-8234-123456789abc',
            aid: 0,
            net: 'tcp',
            type: 'http',
            headers: { Host: 42 }
        });

        expect(() => parseVmess(url)).toThrow(/headers/i);
    });

    it('rejects an unsupported VMess payload security value', () => {
        const url = createVmessUrl({
            v: 2,
            ps: 'Invalid security',
            add: 'vmess.example',
            port: '443',
            id: '12345678-1234-4234-8234-123456789abc',
            aid: 0,
            scy: 'aes-256-gcm',
            net: 'tcp',
            type: 'none'
        });

        expect(() => parseVmess(url)).toThrow(/security/i);
    });

    it('preserves v2rayN certificate SHA constraints in TLS', () => {
        const result = parseVmess(createVmessUrl({
            v: 2,
            ps: 'Pinned certificate',
            add: 'vmess.example',
            port: '443',
            id: '12345678-1234-4234-8234-123456789abc',
            aid: 0,
            net: 'tcp',
            type: 'none',
            tls: 'tls',
            pcs: 'AA'.repeat(32)
        }));

        expect(result.tls.certificate_sha256).toBe('aa'.repeat(32));
    });

    it('rejects a malformed certificate SHA constraint', () => {
        const url = createVmessUrl({
            v: 2,
            ps: 'Malformed pin',
            add: 'vmess.example',
            port: '443',
            id: '12345678-1234-4234-8234-123456789abc',
            aid: 0,
            net: 'tcp',
            type: 'none',
            tls: 'tls',
            pcs: 'AA:BB:CC'
        });

        expect(() => parseVmess(url)).toThrow(/pcs|fingerprint/i);
    });

    it('rejects certificate constraints that this output model would otherwise drop', () => {
        const url = createVmessUrl({
            v: 2,
            ps: 'Pinned certificate',
            add: 'vmess.example',
            port: '443',
            id: '12345678-1234-4234-8234-123456789abc',
            aid: 0,
            net: 'tcp',
            type: 'none',
            tls: 'tls',
            vcn: 'verify.example'
        });

        expect(() => parseVmess(url)).toThrow(/certificate|vcn/i);
    });

    it('treats v2rayN\'s empty optional insecure field as false', () => {
        const result = parseVmess(createVmessUrl({
            v: 2,
            ps: 'Empty insecure',
            add: 'vmess.example',
            port: '443',
            id: '12345678-1234-4234-8234-123456789abc',
            aid: 0,
            net: 'tcp',
            type: 'none',
            tls: 'tls',
            insecure: ''
        }));

        expect(result.tls.insecure).toBe(false);
    });

    it('maps insecure="1" to TLS verification disabled', () => {
        const result = parseVmess(createVmessUrl({
            v: 2,
            ps: 'Insecure TLS',
            add: 'vmess.example',
            port: '443',
            id: '12345678-1234-4234-8234-123456789abc',
            aid: 0,
            net: 'tcp',
            type: 'none',
            tls: 'tls',
            insecure: '1'
        }));

        expect(result.tls.insecure).toBe(true);
    });

    it('rejects an insecure flag outside v2rayN\'s 0/1 values', () => {
        const url = createVmessUrl({
            v: 2,
            ps: 'Invalid insecure flag',
            add: 'vmess.example',
            port: '443',
            id: '12345678-1234-4234-8234-123456789abc',
            aid: 0,
            net: 'tcp',
            type: 'none',
            tls: 'tls',
            insecure: 'yes'
        });

        expect(() => parseVmess(url)).toThrow(/insecure/i);
    });

    it('gives an otherwise valid link without ps a usable derived tag', () => {
        const result = parseVmess(createVmessUrl({
            v: 2,
            add: 'vmess.example',
            port: '443',
            id: '12345678-1234-4234-8234-123456789abc',
            aid: 0,
            net: 'tcp',
            type: 'none'
        }));

        expect(result.tag).toBe('vmess.example:443');
    });

    it('rejects a non-numeric share-format version', () => {
        const url = createVmessUrl({
            v: true,
            ps: 'Invalid version',
            add: 'vmess.example',
            port: '443',
            id: '12345678-1234-4234-8234-123456789abc',
            aid: 0,
            net: 'tcp',
            type: 'none'
        });

        expect(() => parseVmess(url)).toThrow(/version/i);
    });

    it('does not silently drop the legacy skip-cert-verify alias without TLS', () => {
        const url = createVmessUrl({
            v: 2,
            ps: 'Insecure without TLS',
            add: 'vmess.example',
            port: '443',
            id: '12345678-1234-4234-8234-123456789abc',
            aid: 0,
            net: 'tcp',
            type: 'none',
            tls: '',
            'skip-cert-verify': 'true'
        });

        expect(() => parseVmess(url)).toThrow(/TLS/i);
    });

    it('rejects TLS-only settings when TLS is disabled', () => {
        const url = createVmessUrl({
            v: 2,
            ps: 'Fingerprint without TLS',
            add: 'vmess.example',
            port: '443',
            id: '12345678-1234-4234-8234-123456789abc',
            aid: 0,
            net: 'tcp',
            type: 'none',
            tls: '',
            fp: 'chrome'
        });

        expect(() => parseVmess(url)).toThrow(/TLS/i);
    });
});
