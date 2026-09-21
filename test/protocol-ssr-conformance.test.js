import { describe, expect, it } from 'vitest';
import { parseShadowsocksR } from '../src/parsers/protocols/shadowsocksrParser.js';
import { InvalidPayloadError } from '../src/services/errors.js';

const OFFICIAL_EXAMPLE = 'ssr://MTI3LjAuMC4xOjEyMzQ6YXV0aF9hZXMxMjhfbWQ1OmFlcy0xMjgtY2ZiOnRsczEuMl90aWNrZXRfYXV0aDpZV0ZoWW1KaS8_b2Jmc3BhcmFtPVluSmxZV3QzWVRFeExtMXZaUSZyZW1hcmtzPTVyV0w2Sy1WNUxpdDVwYUg';

function encodeBase64Url(value) {
    const bytes = new TextEncoder().encode(value);
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function createUri(payload) {
    return `ssr://${encodeBase64Url(payload)}`;
}

describe('ShadowsocksR URI parser', () => {
    it('parses the original SSR QR-code example with its nested Base64URL fields', () => {
        expect(parseShadowsocksR(OFFICIAL_EXAMPLE)).toEqual({
            tag: '测试中文',
            type: 'shadowsocksr',
            server: '127.0.0.1',
            server_port: 1234,
            method: 'aes-128-cfb',
            password: 'aaabbb',
            protocol: 'auth_aes128_md5',
            protocol_param: undefined,
            obfs: 'tls1.2_ticket_auth',
            obfs_param: 'breakwa11.moe'
        });
    });

    it('accepts padded Base64URL at both layers without splitting Unicode passwords on colons', () => {
        const uri = 'ssr://MjAwMTpkYjg6Ojc6NjU1MzU6YXV0aF9jaGFpbl9hX2NvbXBhdGlibGU6Y2hhY2hhMjAtaWV0ZjpodHRwX3NpbXBsZV9jb21wYXRpYmxlOmNNT2tPbk56T3VXdGx3PT0vP29iZnNwYXJhbT01TDZMTG1WNFlXMXdiR1V2Y0dGMGFEOTRQVEVtZVQweSZwcm90b3BhcmFtPU5ESTY1WS1DNXBXdyZyZW1hcmtzPVNWQjJOaURvaW9Mbmdya2c4Si1hZ0E9PSZncm91cD01cldMNkstVjU3dUU=';

        expect(parseShadowsocksR(uri)).toEqual({
            tag: 'IPv6 节点 🚀',
            type: 'shadowsocksr',
            server: '2001:db8::7',
            server_port: 65535,
            method: 'chacha20-ietf',
            password: 'pä:ss:字',
            protocol: 'auth_chain_a',
            protocol_param: '42:参数',
            obfs: 'http_simple',
            obfs_param: '例.example/path?x=1&y=2'
        });
    });

    it('applies the original client defaults when protocol and obfs fields are empty', () => {
        const uri = createUri('example.com:8388::aes-128-cfb::c2VjcmV0');

        expect(parseShadowsocksR(uri)).toEqual({
            tag: 'example.com:8388',
            type: 'shadowsocksr',
            server: 'example.com',
            server_port: 8388,
            method: 'aes-128-cfb',
            password: 'secret',
            protocol: 'origin',
            protocol_param: undefined,
            obfs: 'plain',
            obfs_param: undefined
        });
    });

    it.each(['', '0', '65536', '-1', '+443', '1.5', '443abc', ' 443'])('rejects the invalid port %j', port => {
        const uri = createUri(`example.com:${port}:origin:aes-128-cfb:plain:c2VjcmV0`);

        expect(() => parseShadowsocksR(uri)).toThrow(InvalidPayloadError);
    });

    it('normalizes bracketed IPv6 hosts and keeps brackets only in the fallback tag', () => {
        const uri = createUri('[2001:db8::9]:443:origin:aes-128-cfb:plain:c2VjcmV0');

        expect(parseShadowsocksR(uri)).toMatchObject({
            tag: '[2001:db8::9]:443',
            server: '2001:db8::9',
            server_port: 443
        });
    });

    it('matches the ssr scheme case-insensitively without accepting a different scheme name', () => {
        expect(parseShadowsocksR(OFFICIAL_EXAMPLE.replace('ssr://', 'SSR://'))).toMatchObject({
            type: 'shadowsocksr',
            server: '127.0.0.1'
        });
        expect(parseShadowsocksR(OFFICIAL_EXAMPLE.replace('ssr://', 'shadowsocksr://'))).toBeNull();
    });

    it.each([
        ':8388:origin:aes-128-cfb:plain:c2VjcmV0',
        'example.com:8388:origin::plain:c2VjcmV0',
        'example.com:8388:origin:aes-128-cfb:plain:',
        'example.com:8388:origin:aes-128-cfb:plain:not*base64',
        'example.com:8388:origin:aes-128-cfb:plain:_w'
    ])('rejects a malformed SSR payload %j', payload => {
        expect(() => parseShadowsocksR(createUri(payload))).toThrow(InvalidPayloadError);
    });

    it('throws for malformed outer Base64URL but ignores non-string input', () => {
        expect(() => parseShadowsocksR('ssr://not*base64')).toThrow(InvalidPayloadError);
        expect(() => parseShadowsocksR('ssr://_w')).toThrow(InvalidPayloadError);
        expect(parseShadowsocksR(undefined)).toBeNull();
    });

    it('uses the last duplicate query value like the original client parser', () => {
        const first = encodeBase64Url('first');
        const last = encodeBase64Url('last');
        const uri = createUri(`example.com:8388:origin:aes-128-cfb:plain:c2VjcmV0/?remarks=${first}&remarks=${last}`);

        expect(parseShadowsocksR(uri).tag).toBe('last');
    });

    it('rejects incorrect padding while accepting valid padded and unpadded Base64URL', () => {
        const unpadded = createUri('example.com:8388:origin:aes-128-cfb:plain:c2VjcmV0');
        const body = unpadded.slice('ssr://'.length);
        const requiredPadding = (4 - (body.length % 4)) % 4;
        const wrongPadding = requiredPadding === 1 ? '==' : '=';

        expect(() => parseShadowsocksR(`${unpadded}${wrongPadding}`)).toThrow(InvalidPayloadError);
        expect(() => parseShadowsocksR(createUri('example.com:8388:origin:aes-128-cfb:plain:c2VjcmV0='))).toThrow(InvalidPayloadError);
    });

    it.each(['remarks', 'protoparam', 'obfsparam', 'group'])('rejects invalid nested Base64URL in %s', parameter => {
        const uri = createUri(`example.com:8388:origin:aes-128-cfb:plain:c2VjcmV0/?${parameter}=not*base64`);

        expect(() => parseShadowsocksR(uri)).toThrow(InvalidPayloadError);
    });
});
