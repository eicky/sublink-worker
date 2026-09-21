import { parseArray, parseBoolParam, parseServerInfo } from '../utils.js';
import { InvalidPayloadError } from '../services/errors.js';
import { parseSurgeValue, splitSurgeFields } from '../utils/surgeProxyLine.js';

function parseParams(parts) {
    const params = Object.create(null);
    for (const part of parts) {
        const index = part.indexOf('=');
        if (index <= 0) throw new InvalidPayloadError('Invalid Surge proxy parameter');
        const key = part.slice(0, index).trim();
        if (params[key] !== undefined) throw new InvalidPayloadError(`Duplicate Surge parameter: ${key}`);
        params[key] = parseSurgeValue(part.slice(index + 1));
    }
    return params;
}

function parseNumber(value, name) {
    if (value === undefined) return undefined;
    if (!/^\d+$/.test(value) || !Number.isSafeInteger(Number(value))) throw new InvalidPayloadError(`Invalid Surge ${name}`);
    return Number(value);
}

function parseTls(params, server, required = false) {
    if (!parseBoolParam(params.tls, { fallback: required, name: 'Surge TLS flag' })) return { enabled: false };
    if (params['client-cert']) throw new InvalidPayloadError('Surge keystore client certificates cannot be converted');
    const disableSni = params.sni === 'off';
    if (!disableSni && params['server-cert-verify-name'] && params['server-cert-verify-name'] !== (params.sni || server)) {
        throw new InvalidPayloadError('Independent Surge SNI and certificate verification names cannot be converted');
    }
    return {
        enabled: true,
        server_name: disableSni ? params['server-cert-verify-name'] || server : params.sni || server,
        insecure: parseBoolParam(params['skip-cert-verify'], { fallback: false, name: 'Surge certificate verification flag' }),
        ...(params.alpn !== undefined ? { alpn: parseArray(params.alpn) || [] } : {}),
        ...(disableSni ? { disable_sni: true } : {}),
        ...(params['server-cert-fingerprint-sha256'] ? { certificate_sha256: params['server-cert-fingerprint-sha256'] } : {})
    };
}

function parseTransport(params) {
    if (params['grpc-service-name']) throw new InvalidPayloadError('Surge does not support gRPC transport');
    if (!parseBoolParam(params.ws, { fallback: false, name: 'Surge WebSocket flag' })) return undefined;
    const headers = {};
    if (params['ws-headers']) {
        for (const header of params['ws-headers'].split('|')) {
            const index = header.indexOf(':');
            if (index <= 0) throw new InvalidPayloadError('Invalid Surge WebSocket header');
            const name = header.slice(0, index).trim();
            headers[name.toLowerCase() === 'host' ? 'Host' : name] = header.slice(index + 1).trim();
        }
    }
    return { type: 'ws', path: params['ws-path'] || '/', ...(Object.keys(headers).length ? { headers } : {}) };
}

export function convertSurgeProxyToObject(line) {
    if (!line || typeof line !== 'string') return null;
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith(';')) return null;
    const equals = trimmed.indexOf('=');
    if (equals < 0) return null;
    const parts = splitSurgeFields(trimmed.slice(equals + 1));
    if (parts.length < 3) return null;
    const type = parts[0].toLowerCase();
    if (!['ss', 'shadowsocks', 'vmess', 'trojan', 'tuic', 'tuic-v5', 'hysteria2', 'hy2', 'anytls'].includes(type)) return null;
    const address = parseSurgeValue(parts[1]);
    const authority = address.includes(':') && !address.startsWith('[') ? `[${address}]` : address;
    const { host, port } = parseServerInfo(`${authority}:${parts[2]}`);
    const params = parseParams(parts.slice(3));
    const common = {
        tag: trimmed.slice(0, equals).trim() || `${host}:${port}`,
        type,
        server: host,
        server_port: port,
        tcp_fast_open: parseBoolParam(params.tfo, { fallback: false, name: 'Surge TFO flag' })
    };
    const hopping = {
        ...(params['port-hopping'] ? { ports: params['port-hopping'].split(';').join(',') } : {}),
        ...(params['port-hopping-interval'] !== undefined ? { hop_interval: parseNumber(params['port-hopping-interval'], 'port-hopping interval') } : {})
    };

    switch (type) {
        case 'ss':
        case 'shadowsocks':
            return {
                ...common, type: 'shadowsocks', method: params['encrypt-method'], password: params.password,
                udp: parseBoolParam(params['udp-relay'], { fallback: false, name: 'Surge UDP relay flag' }),
                ...(params['udp-port'] !== undefined ? { udp_port: parseNumber(params['udp-port'], 'UDP port') } : {}),
                ...(params.obfs ? { plugin: 'obfs-local', plugin_opts: { obfs: params.obfs, ...(params['obfs-host'] ? { 'obfs-host': params['obfs-host'] } : {}), ...(params['obfs-uri'] ? { 'obfs-uri': params['obfs-uri'] } : {}) } } : {})
            };
        case 'vmess': {
            const aead = parseBoolParam(params['vmess-aead'], { fallback: false, name: 'Surge VMess AEAD flag' });
            const cipher = params['encrypt-method'] || 'aes-128-gcm';
            return {
                ...common, uuid: params.username || params.uuid, alter_id: 0,
                security: cipher === 'chacha20-ietf-poly1305' ? 'chacha20-poly1305' : cipher,
                ...(!aead ? { vmess_aead: false } : {}),
                tls: parseTls(params, host), transport: parseTransport(params)
            };
        }
        case 'trojan':
            return { ...common, password: params.password, tls: parseTls(params, host, true), transport: parseTransport(params) };
        case 'tuic':
        case 'tuic-v5': {
            if (type === 'tuic' && (params.uuid !== undefined || params.password !== undefined || params.token === undefined)) throw new InvalidPayloadError('Surge tuic is v4 and requires token; UUID/password requires tuic-v5');
            if (type === 'tuic-v5' && (params.token !== undefined || !params.uuid || params.password === undefined)) throw new InvalidPayloadError('Surge tuic-v5 requires UUID/password, not a v4 token');
            const tls = parseTls(params, host, true);
            tls.alpn ??= ['h3'];
            return {
                ...common, type: 'tuic', ...hopping, tls,
                ...(type === 'tuic' ? { token: params.token } : { uuid: params.uuid, password: params.password })
            };
        }
        case 'hysteria2':
        case 'hy2': {
            const salamander = params['salamander-password'];
            const gecko = params['gecko-password'];
            if (salamander !== undefined && gecko !== undefined) throw new InvalidPayloadError('Surge Salamander and Gecko are mutually exclusive');
            return {
                ...common, type: 'hysteria2', password: params.password, ...hopping,
                tls: parseTls(params, host, true),
                ...(params['download-bandwidth'] !== undefined ? { down_mbps: parseNumber(params['download-bandwidth'], 'download bandwidth') } : {}),
                ...(salamander !== undefined || gecko !== undefined ? { obfs: { type: gecko === undefined ? 'salamander' : 'gecko', password: gecko ?? salamander } } : {})
            };
        }
        case 'anytls':
            return {
                ...common, password: params.password, tls: parseTls(params, host, true),
                ...(params.reuse !== undefined ? { disable_reuse: !parseBoolParam(params.reuse, { name: 'Surge reuse flag' }) } : {})
            };
    }
}
