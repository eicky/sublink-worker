import { createEchConfig, createTlsConfig, getUniqueParamAlias, parseBoolParam, parseCertificateSha256, parseServerInfo, parseUrlParams } from '../../utils.js';
import { InvalidPayloadError } from '../../services/errors.js';

const HYSTERIA2_SCHEMES = new Set(['hysteria2', 'hy2']);
const OBFS_TYPES = new Set(['salamander', 'gecko']);

function parseScheme(url) {
    const match = typeof url === 'string' && url.match(/^([a-z][a-z\d+.-]*):\/\//i);
    const scheme = match?.[1].toLowerCase();
    if (!HYSTERIA2_SCHEMES.has(scheme)) {
        const message = scheme === 'hysteria'
            ? 'Hysteria 1 links are not compatible with Hysteria 2'
            : 'Invalid Hysteria 2 URI scheme';
        throw new InvalidPayloadError(message);
    }
}

function decodeAuth(value) {
    if (value.includes('@')) {
        throw new InvalidPayloadError('Hysteria 2 authentication must percent-encode @');
    }
    try {
        return decodeURIComponent(value);
    } catch (_) {
        throw new InvalidPayloadError('Invalid Hysteria 2 authentication encoding');
    }
}

function parsePortUnion(value, name = 'Hysteria 2 port') {
    const source = String(value ?? '');
    if (!source) throw new InvalidPayloadError(`${name} is missing`);

    return source.split(',').map(part => {
        const match = part.trim().match(/^(\d+)(?:-(\d+))?$/);
        if (!match) throw new InvalidPayloadError(`Invalid ${name}`);
        const start = Number(match[1]);
        const end = Number(match[2] ?? match[1]);
        if (start < 1 || start > 65535 || end < 1 || end > 65535 || start > end) {
            throw new InvalidPayloadError(`Invalid ${name}`);
        }
        return { start, end };
    });
}

function formatPortUnion(ranges) {
    return ranges.map(({ start, end }) => start === end ? String(start) : `${start}-${end}`).join(',');
}

function parseAuthority(addressPart) {
    const authority = addressPart.endsWith('/') ? addressPart.slice(0, -1) : addressPart;
    if (!authority || authority.includes('/')) {
        throw new InvalidPayloadError('Invalid Hysteria 2 server address');
    }

    let auth = '';
    let server = authority;
    const separator = authority.lastIndexOf('@');
    if (separator >= 0) {
        auth = decodeAuth(authority.slice(0, separator));
        server = authority.slice(separator + 1);
    }

    let hostPart;
    let portExpression;
    if (server.startsWith('[')) {
        const closeBracket = server.indexOf(']');
        if (closeBracket < 0) throw new InvalidPayloadError('Invalid Hysteria 2 IPv6 address');
        hostPart = server.slice(0, closeBracket + 1);
        const suffix = server.slice(closeBracket + 1);
        if (suffix) {
            if (!suffix.startsWith(':')) throw new InvalidPayloadError('Invalid Hysteria 2 server address');
            portExpression = suffix.slice(1);
        }
    } else {
        const colon = server.lastIndexOf(':');
        if (colon >= 0) {
            hostPart = server.slice(0, colon);
            portExpression = server.slice(colon + 1);
        } else {
            hostPart = server;
        }
    }

    if (portExpression === undefined) {
        const { host, port } = parseServerInfo(server, 443);
        return { auth, host, port, ports: undefined };
    }

    const ranges = parsePortUnion(portExpression);
    const { host } = parseServerInfo(`${hostPart}:${ranges[0].start}`);
    return {
        auth,
        host,
        port: ranges[0].start,
        ports: ranges.length > 1 || ranges[0].start !== ranges[0].end
            ? formatPortUnion(ranges)
            : undefined
    };
}

function parseInterval(value, name) {
    if (value === undefined) return undefined;
    if (!/^\d+$/.test(String(value))) {
        throw new InvalidPayloadError(`${name} must be an integer number of seconds`);
    }
    const seconds = Number(value);
    if (!Number.isSafeInteger(seconds) || seconds < 5) {
        throw new InvalidPayloadError(`${name} must be at least 5 seconds`);
    }
    return seconds;
}

function parsePacketSize(value, name) {
    if (value === undefined) return undefined;
    if (!/^\d+$/.test(String(value))) throw new InvalidPayloadError(`${name} must be an integer`);
    const size = Number(value);
    if (size < 1 || size > 65535) throw new InvalidPayloadError(`${name} is out of range`);
    return size;
}

function parseObfs(params) {
    const type = params.obfs?.toLowerCase();
    const password = params['obfs-password'];
    const minPacketSize = parsePacketSize(params['obfs-min-packet-size'], 'obfs-min-packet-size');
    const maxPacketSize = parsePacketSize(params['obfs-max-packet-size'], 'obfs-max-packet-size');

    if (type === undefined && password === undefined && minPacketSize === undefined && maxPacketSize === undefined) {
        return undefined;
    }
    if (!type || password === undefined || password === '') {
        throw new InvalidPayloadError('Hysteria 2 obfs requires both type and password');
    }
    if (!OBFS_TYPES.has(type)) {
        throw new InvalidPayloadError(`Unsupported Hysteria 2 obfs type: ${type}`);
    }
    if (type === 'salamander' && new TextEncoder().encode(password).length < 4) {
        throw new InvalidPayloadError('Hysteria 2 Salamander password must be at least 4 bytes');
    }
    if (type !== 'gecko' && (minPacketSize !== undefined || maxPacketSize !== undefined)) {
        throw new InvalidPayloadError('Hysteria 2 obfs packet sizes are only valid for Gecko');
    }
    if (minPacketSize !== undefined && maxPacketSize !== undefined && minPacketSize > maxPacketSize) {
        throw new InvalidPayloadError('Hysteria 2 Gecko minimum packet size exceeds maximum');
    }

    return {
        type,
        password,
        ...(minPacketSize !== undefined ? { min_packet_size: minPacketSize } : {}),
        ...(maxPacketSize !== undefined ? { max_packet_size: maxPacketSize } : {})
    };
}

export function parseHysteria2(url) {
    parseScheme(url);
    const { addressPart, params, name } = parseUrlParams(url);
    const parsed = parseAuthority(addressPart);

    if (params.security !== undefined && params.security !== 'tls') {
        throw new InvalidPayloadError(`Unsupported Hysteria 2 TLS mode: ${params.security}`);
    }
    if (params.auth !== undefined && !parsed.auth) {
        throw new InvalidPayloadError('Hysteria 1 auth query cannot authenticate a Hysteria 2 link');
    }
    if (params.peer !== undefined && params.sni === undefined) {
        throw new InvalidPayloadError('Hysteria 1 peer query is not a Hysteria 2 SNI field');
    }

    const extensionPorts = getUniqueParamAlias(params, ['mport', 'ports'], 'Hysteria 2 port hopping');
    const normalizedExtensionPorts = extensionPorts === undefined
        ? undefined
        : formatPortUnion(parsePortUnion(extensionPorts, 'Hysteria 2 port hopping range'));
    if (parsed.ports && normalizedExtensionPorts && parsed.ports !== normalizedExtensionPorts) {
        throw new InvalidPayloadError('Conflicting Hysteria 2 port hopping settings');
    }

    const hopInterval = parseInterval(
        getUniqueParamAlias(params, ['hop-interval', 'hop_interval'], 'Hysteria 2 hop interval'),
        'Hysteria 2 hop interval'
    );
    const hopIntervalMax = parseInterval(
        getUniqueParamAlias(params, ['hop-interval-max', 'hop_interval_max'], 'Hysteria 2 maximum hop interval'),
        'Hysteria 2 maximum hop interval'
    );
    if (hopIntervalMax !== undefined && hopInterval === undefined) {
        throw new InvalidPayloadError('Hysteria 2 maximum hop interval requires a minimum interval');
    }
    if (hopIntervalMax !== undefined && hopIntervalMax < hopInterval) {
        throw new InvalidPayloadError('Hysteria 2 maximum hop interval is below the minimum');
    }
    const ports = parsed.ports || normalizedExtensionPorts;
    if ((hopInterval !== undefined || hopIntervalMax !== undefined) && !ports) {
        throw new InvalidPayloadError('Hysteria 2 hop interval requires port hopping');
    }

    const tls = createTlsConfig({
        security: 'tls',
        sni: params.sni,
        insecure: parseBoolParam(params.insecure, {
            fallback: false,
            name: 'Hysteria 2 insecure flag'
        })
    });
    const certificateSha256 = parseCertificateSha256(params.pinSHA256, 'Hysteria 2 pinSHA256');
    if (certificateSha256) tls.certificate_sha256 = certificateSha256;
    if (params.ech !== undefined) tls.ech = createEchConfig(params.ech);

    const obfs = parseObfs(params);
    const displayHost = parsed.host.includes(':') ? `[${parsed.host}]` : parsed.host;
    return {
        tag: name || `${displayHost}:${parsed.port}`,
        type: 'hysteria2',
        server: parsed.host,
        server_port: parsed.port,
        password: parsed.auth,
        tls,
        ...(obfs ? { obfs } : {}),
        ...(ports ? { ports } : {}),
        ...(hopInterval !== undefined ? { hop_interval: hopInterval } : {}),
        ...(hopIntervalMax !== undefined ? { hop_interval_max: hopIntervalMax } : {})
    };
}
