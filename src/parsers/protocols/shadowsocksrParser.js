import { base64ToBinary, parseServerInfo } from '../../utils.js';
import { InvalidPayloadError } from '../../services/errors.js';

function decodeBase64Url(value) {
    if (!/^[A-Za-z0-9_-]+={0,2}$/.test(value)) {
        throw new Error('Invalid Base64URL value');
    }

    const binary = base64ToBinary(value);
    const bytes = Uint8Array.from(binary, character => character.charCodeAt(0));
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}

function getLastParam(params, key) {
    const values = params.getAll(key);
    return values.length > 0 ? values[values.length - 1] : null;
}

export function parseShadowsocksR(url) {
    try {
        if (typeof url !== 'string' || url.slice(0, 'ssr://'.length).toLowerCase() !== 'ssr://') return null;

        const payload = decodeBase64Url(url.slice('ssr://'.length));
        const queryIndex = payload.indexOf('?');
        const mainPart = (queryIndex === -1 ? payload : payload.slice(0, queryIndex)).replace(/\/$/, '');
        const query = queryIndex === -1 ? '' : payload.slice(queryIndex + 1);
        const fields = mainPart.split(':');
        const encodedPassword = fields.pop();
        const obfs = fields.pop();
        const method = fields.pop();
        const protocol = fields.pop();
        const port = fields.pop();
        const server = fields.join(':');
        if (!method) throw new InvalidPayloadError('Invalid SSR proxy URI');
        const authority = server.includes(':') && !server.startsWith('[')
            ? `[${server}]:${port}`
            : `${server}:${port}`;
        const { host: normalizedServer, port: serverPort } = parseServerInfo(authority);

        const params = new URLSearchParams(query);
        const remarks = getLastParam(params, 'remarks');
        const protocolParam = getLastParam(params, 'protoparam');
        const obfsParam = getLastParam(params, 'obfsparam');
        const group = getLastParam(params, 'group');
        // Group is subscription metadata, not an outbound protocol field.
        if (group) decodeBase64Url(group);
        const tagServer = normalizedServer.includes(':') ? `[${normalizedServer}]` : normalizedServer;

        return {
            tag: remarks ? decodeBase64Url(remarks) : `${tagServer}:${serverPort}`,
            type: 'shadowsocksr',
            server: normalizedServer,
            server_port: serverPort,
            method,
            password: decodeBase64Url(encodedPassword),
            protocol: (protocol || 'origin').replace(/_compatible/g, ''),
            protocol_param: protocolParam ? decodeBase64Url(protocolParam) : undefined,
            obfs: (obfs || 'plain').replace(/_compatible/g, ''),
            obfs_param: obfsParam ? decodeBase64Url(obfsParam) : undefined
        };
    } catch (error) {
        if (error instanceof InvalidPayloadError) throw error;
        throw new InvalidPayloadError('Invalid SSR proxy URI');
    }
}
