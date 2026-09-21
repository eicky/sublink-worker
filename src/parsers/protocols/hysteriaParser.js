import { createTlsConfig, parseBoolParam, parseProxyUri } from '../../utils.js';
import { InvalidPayloadError } from '../../services/errors.js';

const PROTOCOL_ALIASES = {
    udp: 'udp',
    'wechat-video': 'wechat-video',
    wechat: 'wechat-video',
    faketcp: 'faketcp'
};

function parseMbps(value, name) {
    if (value === undefined || value === '') {
        throw new InvalidPayloadError(`Hysteria 1 ${name} is required`);
    }
    if (!/^\d+$/.test(String(value))) {
        throw new InvalidPayloadError(`Hysteria 1 ${name} must be a positive integer`);
    }
    const result = Number(value);
    if (!Number.isSafeInteger(result) || result <= 0) {
        throw new InvalidPayloadError(`Hysteria 1 ${name} must be a positive integer`);
    }
    return result;
}

function parseProtocol(value) {
    const normalized = String(value ?? 'udp').toLowerCase();
    const protocol = PROTOCOL_ALIASES[normalized];
    if (!protocol) throw new InvalidPayloadError(`Unsupported Hysteria 1 protocol: ${value}`);
    return protocol;
}

function parseObfs(params) {
    const type = params.obfs?.toLowerCase();
    const password = params.obfsParam;
    if (!type) {
        if (password !== undefined && password !== '') {
            throw new InvalidPayloadError('Hysteria 1 obfsParam requires obfs=xplus');
        }
        return undefined;
    }
    if (type !== 'xplus') throw new InvalidPayloadError(`Unsupported Hysteria 1 obfs type: ${params.obfs}`);
    if (!password) throw new InvalidPayloadError('Hysteria 1 xplus obfs requires obfsParam');
    return password;
}

export function parseHysteria(url) {
    if (typeof url !== 'string' || !/^hysteria:\/\//i.test(url)) {
        throw new InvalidPayloadError('Invalid Hysteria 1 URI scheme');
    }

    const { userinfo, host, port, params, fragmentName } = parseProxyUri(url, undefined, { requireUserinfo: false });
    if (userinfo) throw new InvalidPayloadError('Hysteria 1 URI does not use userinfo authentication');
    const protocol = parseProtocol(params.protocol);
    const upMbps = parseMbps(params.upmbps, 'upmbps');
    const downMbps = parseMbps(params.downmbps, 'downmbps');
    const insecure = parseBoolParam(params.insecure, {
        fallback: false,
        name: 'Hysteria 1 insecure flag'
    });
    const tls = createTlsConfig({
        security: 'tls',
        sni: params.peer,
        insecure,
        alpn: params.alpn ?? 'hysteria'
    });
    const obfs = parseObfs(params);
    const displayHost = host.includes(':') ? `[${host}]` : host;

    return {
        tag: fragmentName || `${displayHost}:${port}`,
        type: 'hysteria',
        server: host,
        server_port: port,
        ...(params.auth !== undefined && params.auth !== '' ? { auth_str: params.auth } : {}),
        up_mbps: upMbps,
        down_mbps: downMbps,
        protocol,
        ...(obfs !== undefined ? { obfs } : {}),
        tls
    };
}
