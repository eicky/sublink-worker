import { describe, expect, it } from 'vitest';
import { parseUrlParams, parseServerInfo, createTlsConfig, createTransportConfig, decodeBase64, encodeBase64 } from '../src/utils.js';
import { parseTrojan } from '../src/parsers/protocols/trojanParser.js';
import { parseVless } from '../src/parsers/protocols/vlessParser.js';

const uuid = 'd342d11e-d424-4583-b36e-524ab1f0afa4';

describe('share-link URI syntax', () => {
    it('separates a fragment even when there is no query', () => {
        expect(parseUrlParams('trojan://pass@example.com:443#%E9%A6%99%E6%B8%AF%20%231')).toEqual({
            addressPart: 'pass@example.com:443', params: {}, name: '香港 #1'
        });
    });

    it('does not interpret question marks in the fragment as parameters', () => {
        expect(parseUrlParams('trojan://pass@example.com:443#name?security=none')).toEqual({
            addressPart: 'pass@example.com:443', params: {}, name: 'name?security=none'
        });
    });

    it('decodes query values once without splitting an embedded scheme or equals sign', () => {
        const result = parseUrlParams(`vless://${uuid}@example.com:443?path=%2Fhttps%3A%2F%2Fexample.test%3Fa%3Db%253Dc#test`);
        expect(result.params.path).toBe('/https://example.test?a=b%3Dc');
    });

    it('rejects conflicting duplicate parameters instead of selecting one silently', () => {
        expect(() => parseUrlParams(`vless://${uuid}@example.com:443?security=tls&security=none`)).toThrow(/duplicate/i);
    });

    it('parses bracketed IPv6 and an optional root slash', () => {
        expect(parseServerInfo('[2001:db8::1]:8443/')).toEqual({ host: '2001:db8::1', port: 8443 });
    });

    it('uses a default port only when the caller explicitly provides one', () => {
        expect(parseServerInfo('example.com', 443)).toEqual({ host: 'example.com', port: 443 });
        expect(() => parseServerInfo('example.com')).toThrow(/port/i);
    });

    it.each(['example.com:0', 'example.com:65536', 'example.com:443junk', 'example.com:-1', 'example.com:', '[2001:db8::1', '2001:db8::1:443'])('rejects an invalid authority: %s', authority => {
        expect(() => parseServerInfo(authority)).toThrow();
    });

    it('decodes Unicode base64url with omitted padding', () => {
        const value = '节点🙂:p@ss?';
        const encoded = encodeBase64(value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        expect(decodeBase64(encoded)).toBe(value);
    });

    it.each(['a', '%%%invalid%%%', 'YW=Jj', 'YWJj==='])('rejects malformed base64: %s', value => {
        expect(() => decodeBase64(value)).toThrow();
    });
});

describe('TLS parameter semantics', () => {
    it.each(['0', 'false', 'FALSE'])('does not treat allowInsecure=%s as true', value => {
        expect(createTlsConfig({ security: 'tls', allowInsecure: value }).insecure).toBe(false);
    });

    it.each(['1', 'true', 'TRUE'])('accepts an explicit allowInsecure=%s', value => {
        expect(createTlsConfig({ security: 'tls', allowInsecure: value }).insecure).toBe(true);
    });

    it('does not override an explicit false with a lower-priority alias', () => {
        expect(createTlsConfig({ security: 'tls', allowInsecure: '0', insecure: '1' }).insecure).toBe(false);
    });

    it('preserves SNI, ALPN and the requested client fingerprint', () => {
        expect(createTlsConfig({ security: 'tls', peer: 'sni.example', alpn: 'h2,http/1.1', fp: 'firefox' })).toMatchObject({
            enabled: true,
            server_name: 'sni.example',
            alpn: ['h2', 'http/1.1'],
            utls: { enabled: true, fingerprint: 'firefox' }
        });
    });

    it('honors an explicit SNI before peer and Host', () => {
        expect(createTlsConfig({ security: 'tls', sni: 'sni.example', peer: 'peer.example', host: 'host.example' }).server_name).toBe('sni.example');
    });

    it('preserves the REALITY fingerprint instead of forcing chrome', () => {
        const result = parseVless(`vless://${uuid}@example.com:443?security=reality&pbk=public-key&sid=abcd&fp=firefox#Reality`);
        expect(result.tls.reality).toEqual({ enabled: true, public_key: 'public-key', short_id: 'abcd' });
        expect(result.tls.utls.fingerprint).toBe('firefox');
    });

    it('preserves a VLESS pcs certificate SHA-256 pin, including OpenSSL formatting', () => {
        const pin = Array(32).fill('AB').join(':');
        const proxy = parseVless(`vless://${uuid}@node.example:443?security=tls&pcs=${encodeURIComponent(` ${pin} `)}`);
        expect(proxy.tls).toMatchObject({ enabled: true, insecure: false, certificate_sha256: 'ab'.repeat(32) });
    });

    it.each(['', ' '])('ignores an empty optional pcs field (%j)', pcs => {
        expect(createTlsConfig({ security: 'tls', pcs })).not.toHaveProperty('certificate_sha256');
    });

    it.each(['invalid', 'ab'.repeat(31), `${'ab'.repeat(32)},${'cd'.repeat(32)}`])('rejects certificate pins that cannot be represented (%s)', pcs => {
        expect(() => createTlsConfig({ security: 'tls', pcs })).toThrow(/fingerprint/);
    });

    it.each(['none', 'reality'])('does not discard certificate pinning under security=%s', security => {
        expect(() => createTlsConfig({ security, pbk: 'public-key', pcs: 'ab'.repeat(32) })).toThrow(/pcs|pinning/);
    });

    it('rejects unknown TLS modes and incomplete REALITY settings', () => {
        expect(() => createTlsConfig({ security: 'unknown' })).toThrow();
        expect(() => createTlsConfig({ security: 'reality' })).toThrow();
    });
});

describe('transport semantics', () => {
    it.each([undefined, 'tcp', 'raw'])('omits an unnecessary transport for %s', type => {
        expect(createTransportConfig({ type })).toBeUndefined();
    });

    it('preserves the WebSocket Host and uses the documented default path', () => {
        expect(createTransportConfig({ type: 'ws', host: 'cdn.example' })).toEqual({
            type: 'ws', path: '/', headers: { Host: 'cdn.example' }
        });
    });

    it('normalizes HTTP/2 aliases to the sing-box-like HTTP transport', () => {
        expect(createTransportConfig({ type: 'h2', host: 'a.example,b.example', path: '/h2' })).toEqual({
            type: 'http', host: ['a.example', 'b.example'], path: '/h2'
        });
    });

    it('extracts Xray WebSocket early data without sending the ed parameter to the server', () => {
        expect(createTransportConfig({ type: 'ws', path: '/ws?ed=2048&token=a%2Bb' })).toEqual({
            type: 'ws', path: '/ws?token=a%2Bb', max_early_data: 2048, early_data_header_name: 'Sec-WebSocket-Protocol'
        });
    });

    it('rejects invalid WebSocket early-data sizes instead of changing the handshake', () => {
        expect(() => createTransportConfig({ type: 'ws', path: '/ws?ed=invalid' })).toThrow(/early.data/i);
    });

    it('puts HTTPUpgrade host in its own field, not WebSocket headers', () => {
        expect(createTransportConfig({ type: 'httpupgrade', host: 'cdn.example', path: '/upgrade' })).toEqual({
            type: 'httpupgrade', host: 'cdn.example', path: '/upgrade'
        });
    });

    it('preserves gRPC service names without unrelated path or Host fields', () => {
        expect(createTransportConfig({ type: 'grpc', serviceName: 'service/name', host: 'unused.example' })).toEqual({
            type: 'grpc', service_name: 'service/name'
        });
    });
});

describe('Trojan and VLESS share links', () => {
    it('preserves the previously lost Trojan peer and ALPN and omits empty transport', () => {
        const proxy = parseTrojan('trojan://pass@node.example:443?peer=sni.example&alpn=h2%2Chttp%2F1.1#test');
        expect(proxy.tls).toMatchObject({ enabled: true, server_name: 'sni.example', alpn: ['h2', 'http/1.1'] });
        expect(proxy.transport).toBeUndefined();
    });

    it('decodes the password exactly once and preserves the fragment-only name', () => {
        const proxy = parseTrojan('trojan://p%40ss%3Aword%2520@[2001:db8::1]:443#%E8%8A%82%E7%82%B9');
        expect(proxy).toMatchObject({ password: 'p@ss:word%20', server: '2001:db8::1', server_port: 443, tag: '节点' });
    });

    it('gives unnamed links a usable tag', () => {
        expect(parseTrojan('trojan://pass@example.com:443').tag).toBe('example.com:443');
        expect(parseVless(`vless://${uuid}@example.com:443`).tag).toBe('example.com:443');
    });

    it('does not manufacture TLS or a transport for plain VLESS', () => {
        const proxy = parseVless(`vless://${uuid}@example.com:80#Plain`);
        expect(proxy).toMatchObject({ tag: 'Plain', uuid, server: 'example.com', server_port: 80, tls: { enabled: false } });
        expect(proxy.transport).toBeUndefined();
        expect(proxy.network).toBeUndefined();
    });

    it('does not mistake a Trojan flow parameter for a supported sing-box field', () => {
        expect(parseTrojan('trojan://pass@example.com:443?flow=xtls-rprx-vision').flow).toBeUndefined();
    });
});
