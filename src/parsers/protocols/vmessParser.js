import { createEchConfig, createTlsConfig, createTransportConfig, decodeBase64, parseBool, parseCertificateSha256, parseProxyUri, parseServerInfo } from '../../utils.js';
import { InvalidPayloadError } from '../../services/errors.js';

const VMESS_SECURITIES = new Set(['auto', 'aes-128-gcm', 'chacha20-poly1305', 'none', 'zero']);
const VMESS_URI_SECURITIES = new Set(['auto', 'aes-128-gcm', 'chacha20-poly1305', 'none']);
const VMESS_UUID_PATTERN = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i;
const VMESS_URI_GRPC_MODES = new Set(['gun', 'multi', 'guna']);
const VMESS_URI_FIELDS = new Set([
    'type', 'encryption', 'security', 'mtu', 'tti', 'path', 'host', 'serviceName',
    'mode', 'authority', 'extra', 'fm', 'fp', 'sni', 'alpn', 'ech', 'pcs', 'vcn',
    'pbk', 'sid', 'pqv', 'spx'
]);
const VMESS_URI_TLS_FIELDS = ['fp', 'sni', 'alpn', 'ech', 'pcs', 'vcn', 'pbk', 'sid', 'pqv', 'spx'];
const VMESS_URI_TLS_ONLY_FIELDS = ['alpn', 'ech', 'pcs', 'vcn'];
const VMESS_URI_REALITY_ONLY_FIELDS = ['pbk', 'sid', 'pqv', 'spx'];
const VMESS_URI_TRANSPORT_FIELDS = ['mtu', 'tti', 'path', 'host', 'serviceName', 'mode', 'authority', 'extra'];
const VMESS_URI_TRANSPORTS = {
    tcp: new Set(),
    kcp: new Set(['mtu', 'tti']),
    ws: new Set(['path', 'host']),
    http: new Set(['path', 'host']),
    h2: new Set(['path', 'host']),
    grpc: new Set(['serviceName', 'mode', 'authority']),
    httpupgrade: new Set(['path', 'host']),
    xhttp: new Set(['path', 'host', 'mode', 'extra'])
};
const VMESS_TRANSPORT_TYPES = {
    tcp: new Set(['tcp', 'none', 'http']),
    ws: new Set(['ws', 'none']),
    http: new Set(['http', 'none']),
    h2: new Set(['h2', 'none']),
    grpc: new Set(['grpc', 'none', 'gun', 'multi']),
    httpupgrade: new Set(['httpupgrade', 'none']),
    xhttp: new Set(['xhttp', 'none', 'auto', 'packet-up', 'stream-up', 'stream-one'])
};

const STRING_FIELDS = [
    'ps', 'add', 'scy', 'net', 'type', 'host', 'path', 'tls', 'sni', 'alpn', 'fp',
    'insecure', 'vcn', 'pcs', 'serviceName', 'method'
];
const VMESS_FIELD_NAMES = new Map([
    'v', 'ps', 'add', 'port', 'id', 'aid', 'scy', 'net', 'type', 'host', 'path', 'tls',
    'sni', 'alpn', 'fp', 'insecure', 'vcn', 'pcs', 'headers', 'method', 'skip-cert-verify'
].map(field => [field.toLowerCase(), field]));
VMESS_FIELD_NAMES.set('servicename', 'serviceName');

function normalizeVmessConfig(config) {
    const normalized = Object.create(null);
    for (const [field, value] of Object.entries(config)) {
        const canonical = VMESS_FIELD_NAMES.get(field.toLowerCase()) || field;
        if (Object.hasOwn(normalized, canonical)) {
            throw new InvalidPayloadError(`Duplicate VMess field: ${canonical}`);
        }
        normalized[canonical] = value;
    }
    return normalized;
}

function validateVmessFields(config) {
    for (const field of STRING_FIELDS) {
        if (config[field] !== undefined && typeof config[field] !== 'string') {
            throw new InvalidPayloadError(`VMess ${field} must be a string`);
        }
    }
    if (!config.add) {
        throw new InvalidPayloadError('VMess add must be a non-empty server address');
    }
    if (config.headers !== undefined) {
        if (!config.headers || typeof config.headers !== 'object' || Array.isArray(config.headers)) {
            throw new InvalidPayloadError('VMess headers must be an object');
        }
        for (const [key, value] of Object.entries(config.headers)) {
            const validValue = typeof value === 'string' ||
                (Array.isArray(value) && value.every(entry => typeof entry === 'string'));
            if (!key || !validValue) {
                throw new InvalidPayloadError('VMess headers must contain string values');
            }
        }
    }
}

function parseVmessCertificateSha256(value) {
    return value === undefined || String(value).trim() === ''
        ? undefined
        : parseCertificateSha256(value, 'VMess pcs');
}

function parseInteger(value, field, minimum, maximum) {
    const validString = typeof value === 'string' && /^\d+$/.test(value);
    if (!(Number.isInteger(value) || validString)) {
        throw new InvalidPayloadError(`VMess ${field} must be an integer`);
    }
    const parsed = Number(value);
    if (parsed < minimum || parsed > maximum) {
        throw new InvalidPayloadError(`VMess ${field} must be between ${minimum} and ${maximum}`);
    }
    return parsed;
}

function normalizeArray(value) {
    if (!value) return undefined;
    return Array.isArray(value) ? value : [value];
}

function normalizeHostList(value) {
    if (!value) return undefined;
    const normalized = value.split(',').map(entry => entry.trim()).filter(Boolean);
    return normalized.length > 0 ? normalized : undefined;
}

function buildHttpHeaders(vmessConfig) {
    const hostHeader = normalizeHostList(vmessConfig.host);
    if (vmessConfig.headers && typeof vmessConfig.headers === 'object') {
        const normalized = {};
        Object.entries(vmessConfig.headers).forEach(([key, value]) => {
            const normalizedValue = normalizeArray(value)?.map(entry => `${entry}`);
            if (normalizedValue && normalizedValue.length > 0) {
                normalized[key.toLowerCase() === 'host' ? 'Host' : key] = normalizedValue;
            }
        });
        if (hostHeader && !normalized.Host) {
            normalized.Host = hostHeader;
        }
        if (Object.keys(normalized).length > 0) {
            return normalized;
        }
    }
    return hostHeader ? { Host: hostHeader } : undefined;
}

function parseUuid(value) {
    let uuid;
    try {
        uuid = decodeURIComponent(value);
    } catch (_) {
        throw new InvalidPayloadError('Invalid VMess UUID encoding');
    }
    if (!VMESS_UUID_PATTERN.test(uuid)) {
        throw new InvalidPayloadError('VMess id must be a valid UUID');
    }
    return uuid;
}

function hasAuthorityUserinfo(url) {
    const payload = url.slice(url.indexOf('://') + 3);
    const boundary = payload.search(/[?#]/);
    const authority = boundary < 0 ? payload : payload.slice(0, boundary);
    return authority.lastIndexOf('@') > 0;
}

function parseStandardVmess(url) {
    const { userinfo, host, port, params, fragmentName } = parseProxyUri(url);
    for (const field of Object.keys(params)) {
        if (!VMESS_URI_FIELDS.has(field)) {
            throw new InvalidPayloadError(`Unsupported VMess URI query parameter: ${field}`);
        }
    }
    const uuid = parseUuid(userinfo);
    const transportType = params.type ?? 'tcp';
    if (!Object.hasOwn(VMESS_URI_TRANSPORTS, transportType)) {
        throw new InvalidPayloadError(`Unsupported VMess transport: ${transportType}`);
    }
    for (const field of VMESS_URI_TRANSPORT_FIELDS) {
        if (Object.hasOwn(params, field) && !VMESS_URI_TRANSPORTS[transportType].has(field)) {
            throw new InvalidPayloadError(`VMess URI field ${field} is not valid for ${transportType} transport`);
        }
    }
    for (const field of ['sni', 'fp', 'alpn']) {
        if (Object.hasOwn(params, field) && params[field] === '') {
            throw new InvalidPayloadError(`VMess URI field ${field} must not be empty`);
        }
    }
    if (['ws', 'httpupgrade', 'xhttp'].includes(params.type) && Object.hasOwn(params, 'path') && params.path === '') {
        throw new InvalidPayloadError('VMess URI field path must not be empty');
    }
    if (params.type === 'grpc' && Object.hasOwn(params, 'serviceName') && params.serviceName === '') {
        throw new InvalidPayloadError('VMess URI field serviceName must not be empty');
    }
    const security = params.encryption === undefined ? 'auto' : params.encryption;
    if (!VMESS_URI_SECURITIES.has(security)) {
        throw new InvalidPayloadError(`Unsupported VMess encryption: ${security}`);
    }
    if (params.type === 'grpc' && params.mode !== undefined && !VMESS_URI_GRPC_MODES.has(params.mode)) {
        throw new InvalidPayloadError(`Unsupported VMess gRPC mode: ${params.mode}`);
    }
    const tlsMode = params.security ?? 'none';
    if (tlsMode === 'none' && VMESS_URI_TLS_FIELDS.some(field => Object.hasOwn(params, field))) {
        throw new InvalidPayloadError('VMess TLS fields require security=tls or security=reality');
    }
    if (tlsMode === 'tls' && VMESS_URI_REALITY_ONLY_FIELDS.some(field => Object.hasOwn(params, field))) {
        throw new InvalidPayloadError('VMess REALITY fields require security=reality');
    }
    if (tlsMode === 'reality' && VMESS_URI_TLS_ONLY_FIELDS.some(field => Object.hasOwn(params, field))) {
        throw new InvalidPayloadError('VMess TLS-only fields are not valid with security=reality');
    }
    const { pcs, ech, ...tlsParams } = params;
    const certificateSha256 = parseVmessCertificateSha256(pcs);
    const tls = createTlsConfig({
        ...tlsParams,
        sni: params.sni || host,
        fp: params.fp || (params.security && params.security !== 'none' ? 'chrome' : undefined)
    });
    if (certificateSha256) tls.certificate_sha256 = certificateSha256;
    if (ech) tls.ech = createEchConfig(ech);
    const displayServer = host.includes(':') ? `[${host}]` : host;
    return {
        tag: fragmentName || `${displayServer}:${port}`,
        type: 'vmess',
        server: host,
        server_port: port,
        uuid,
        alter_id: 0,
        security,
        tcp_fast_open: false,
        transport: createTransportConfig(params),
        tls: tls.enabled ? tls : undefined
    };
}

export function parseVmess(url) {
    const normalizedUrl = typeof url === 'string' ? url.trim() : '';
    if (!/^vmess:\/\//i.test(normalizedUrl)) {
        throw new InvalidPayloadError('Invalid VMess URI scheme');
    }
    if (hasAuthorityUserinfo(normalizedUrl)) {
        return parseStandardVmess(normalizedUrl);
    }

    let base64WithFragment = normalizedUrl.slice(normalizedUrl.indexOf('://') + 3);
    let tagOverride;
    const hashPos = base64WithFragment.indexOf('#');
    if (hashPos >= 0) {
        try {
            tagOverride = decodeURIComponent(base64WithFragment.slice(hashPos + 1));
        } catch (_) {
            throw new InvalidPayloadError('Invalid VMess fragment encoding');
        }
        base64WithFragment = base64WithFragment.slice(0, hashPos);
    }

    let vmessConfig;
    try {
        vmessConfig = JSON.parse(decodeBase64(base64WithFragment));
    } catch (error) {
        if (error instanceof InvalidPayloadError) throw error;
        throw new InvalidPayloadError('Invalid VMess Base64 JSON payload');
    }
    if (!vmessConfig || typeof vmessConfig !== 'object' || Array.isArray(vmessConfig)) {
        throw new InvalidPayloadError('VMess payload must be a JSON object');
    }
    vmessConfig = normalizeVmessConfig(vmessConfig);
    validateVmessFields(vmessConfig);
    if (vmessConfig.v !== undefined) {
        parseInteger(vmessConfig.v, 'version', 0, Number.MAX_SAFE_INTEGER);
    }
    if (vmessConfig.vcn) {
        throw new InvalidPayloadError('VMess certificate verification name (vcn) is not supported');
    }
    const certificateSha256 = parseVmessCertificateSha256(vmessConfig.pcs);
    const serverPort = parseInteger(vmessConfig.port, 'port', 1, 65535);
    const address = vmessConfig.add.trim();
    const authority = address.includes(':') ? `[${address}]:${serverPort}` : `${address}:${serverPort}`;
    const { host: server } = parseServerInfo(authority);
    if (typeof vmessConfig.id !== 'string' || !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(vmessConfig.id)) {
        throw new InvalidPayloadError('VMess id must be a valid UUID');
    }
    const alterId = vmessConfig.aid === undefined
        ? 0
        : parseInteger(vmessConfig.aid, 'alterId', 0, 65535);
    const security = vmessConfig.scy || 'auto';
    if (!VMESS_SECURITIES.has(security)) {
        throw new InvalidPayloadError(`Unsupported VMess security: ${security}`);
    }
    if (vmessConfig.insecure && !['0', '1'].includes(vmessConfig.insecure)) {
        throw new InvalidPayloadError('VMess insecure must be "0" or "1"');
    }
    const insecureValue = vmessConfig.insecure ?? vmessConfig['skip-cert-verify'];
    const insecureEnabled = insecureValue === '' ? false : parseBool(insecureValue, undefined);
    if (insecureValue !== undefined && insecureEnabled === undefined) {
        throw new InvalidPayloadError('VMess insecure flag must be boolean or 0/1');
    }
    const tlsMode = vmessConfig.tls || 'none';
    if (tlsMode === 'none' && (
        vmessConfig.sni || vmessConfig.alpn || (vmessConfig.fp && vmessConfig.fp !== 'none') ||
        certificateSha256 || insecureEnabled
    )) {
        throw new InvalidPayloadError('VMess TLS settings require tls="tls"');
    }
    // Legacy v2rayN JSON has a Host fallback that the authority-style proposal does not.
    const fallbackSni = ['tcp', 'ws', 'httpupgrade', 'xhttp', 'grpc'].includes(vmessConfig.net || 'tcp')
        ? normalizeHostList(vmessConfig.host)?.[0]
        : undefined;
    const tls = createTlsConfig({
        security: tlsMode,
        sni: vmessConfig.sni || fallbackSni,
        alpn: vmessConfig.alpn,
        fp: vmessConfig.fp,
        insecure: insecureValue === '' ? undefined : insecureValue
    });
    if (certificateSha256) {
        tls.certificate_sha256 = certificateSha256;
    }
    let transport;
    const networkType = vmessConfig.net || 'tcp';
    if (!Object.hasOwn(VMESS_TRANSPORT_TYPES, networkType)) {
        throw new InvalidPayloadError(`Unsupported VMess transport: ${networkType}`);
    }
    const transportType = vmessConfig.type || networkType;
    if (!VMESS_TRANSPORT_TYPES[networkType].has(transportType)) {
        throw new InvalidPayloadError(`Unsupported VMess ${networkType} transport type: ${transportType}`);
    }

    if (networkType === 'ws') {
        transport = createTransportConfig({ type: 'ws', host: vmessConfig.host, path: vmessConfig.path });
    } else if (networkType === 'tcp' && transportType === 'http') {
        transport = createTransportConfig({
            type: 'tcp',
            headerType: 'http',
            host: vmessConfig.host,
            path: vmessConfig.path
        });
        transport.method = vmessConfig.method || 'GET';
        transport.headers = buildHttpHeaders(vmessConfig);
    } else if (networkType === 'http' || networkType === 'h2') {
        transport = createTransportConfig({ type: networkType, host: vmessConfig.host, path: vmessConfig.path });
    } else if (networkType === 'grpc') {
        transport = createTransportConfig({
            type: 'grpc',
            serviceName: vmessConfig.path || vmessConfig.serviceName,
            authority: vmessConfig.host,
            mode: ['gun', 'multi'].includes(vmessConfig.type) ? vmessConfig.type : undefined
        });
    } else if (networkType === 'httpupgrade') {
        transport = createTransportConfig({ type: 'httpupgrade', host: vmessConfig.host, path: vmessConfig.path });
    } else if (networkType === 'xhttp') {
        transport = createTransportConfig({
            type: 'xhttp',
            host: vmessConfig.host,
            path: vmessConfig.path,
            mode: ['auto', 'packet-up', 'stream-up', 'stream-one'].includes(vmessConfig.type)
                ? vmessConfig.type
                : undefined
        });
    }

    const displayServer = server.includes(':') ? `[${server}]` : server;
    return {
        tag: tagOverride || vmessConfig.ps || `${displayServer}:${serverPort}`,
        type: 'vmess',
        server,
        server_port: serverPort,
        uuid: vmessConfig.id,
        alter_id: alterId,
        security,
        tcp_fast_open: false,
        transport,
        tls: tls.enabled ? tls : undefined
    };
}
