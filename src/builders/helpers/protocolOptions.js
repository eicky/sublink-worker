import { parseBool, parseArray, base64ToBinary, base64FromBinary } from '../../utils.js';
import { InvalidConfigError } from '../../services/errors.js';

export function unsupportedProxy(proxy, client, reason) {
    throw new InvalidConfigError(`Cannot convert ${proxy.tag || proxy.type} (${proxy.type}) to ${client}: ${reason}`);
}

export function proxyTls(proxy, skipCertVerify = false) {
    if (!proxy.tls) return undefined;
    const tls = { ...proxy.tls, ...(proxy.alpn && !proxy.tls.alpn ? { alpn: parseArray(proxy.alpn) } : {}) };
    if (skipCertVerify && tls.enabled && !tls.reality?.enabled) {
        tls.insecure = true;
        // Pins can still enforce verification even when the client's insecure flag is set.
        delete tls.certificate_sha256;
        delete tls.certificate_public_key_sha256;
        delete tls.certificate;
        delete tls.certificate_path;
    }
    return tls;
}

export function clashEch(proxy, ech) {
    if (ech.enabled === false) return { enable: false };
    if (ech.config_path || ech.query_server_name) unsupportedProxy(proxy, 'Mihomo', 'ECH config paths or custom discovery names cannot be converted');
    const text = (Array.isArray(ech.config) ? ech.config.join('\n') : ech.config || '').trim();
    if (!text) return { enable: true };
    const match = text.match(/^-----BEGIN ECH CONFIGS-----\s*([A-Za-z0-9+/=\s]+)\s*-----END ECH CONFIGS-----$/);
    if (!match) unsupportedProxy(proxy, 'Mihomo', 'ECH config must contain a single ECH CONFIGS PEM block');
    return { enable: true, config: base64FromBinary(base64ToBinary(match[1])) };
}

export function proxyTransport(proxy) {
    const transport = proxy.transport;
    if (!transport?.type || transport.type === 'tcp' || transport.type === 'raw') return undefined;
    return transport.type === 'h2' ? { ...transport, type: 'http' } : { ...transport };
}

export function durationSeconds(value) {
    if (value === undefined || value === null) return undefined;
    if (typeof value === 'number' || /^\d+(?:\.\d+)?$/.test(String(value))) {
        const result = Number(value);
        if (Number.isFinite(result) && result >= 0) return result;
    }
    if (typeof value === 'string' && /^(?:\d+(?:\.\d+)?(?:ns|us|µs|ms|s|m|h))+$/.test(value)) {
        const units = { ns: 1e-9, us: 1e-6, 'µs': 1e-6, ms: 0.001, s: 1, m: 60, h: 3600 };
        return [...value.matchAll(/(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)/g)]
            .reduce((total, match) => total + Number(match[1]) * units[match[2]], 0);
    }
    throw new InvalidConfigError('Invalid protocol duration');
}

export function durationString(value) {
    return value === undefined || value === null ? undefined : `${durationSeconds(value)}s`;
}

export function portRanges(value, separator = ':') {
    if (value === undefined || value === null || value === '') return undefined;
    const parts = Array.isArray(value) ? value : String(value).split(/[,/]/);
    return parts.map(part => {
        const match = String(part).trim().match(/^(\d+)(?:[:-](\d+))?$/);
        if (!match || match.slice(1).filter(Boolean).some(port => Number(port) < 1 || Number(port) > 65535)) {
            throw new InvalidConfigError('Invalid port hopping range');
        }
        const start = Number(match[1]);
        const end = match[2] === undefined ? start : Number(match[2]);
        return start === end && separator !== ':' ? String(start) : `${Math.min(start, end)}${separator}${Math.max(start, end)}`;
    });
}

export function parsePluginOptions(value) {
    if (!value) return {};
    if (typeof value === 'object') return { ...value };
    const result = Object.create(null);
    let key = '', text = '', inValue = false, escaped = false;
    const flush = () => {
        if (key) result[key] = inValue ? text : true;
        key = ''; text = ''; inValue = false;
    };
    for (const char of String(value)) {
        if (escaped) {
            if (inValue) text += char; else key += char;
            escaped = false;
        } else if (char === '\\') {
            escaped = true;
        } else if (char === ';') {
            flush();
        } else if (char === '=' && !inValue) {
            inValue = true;
        } else if (inValue) {
            text += char;
        } else {
            key += char;
        }
    }
    if (escaped) throw new InvalidConfigError('Invalid plugin option escape');
    flush();
    return result;
}

export function normalizePlugin(proxy) {
    if (!proxy.plugin) return undefined;
    const obfs = ['obfs', 'simple-obfs', 'obfs-local'].includes(proxy.plugin);
    const options = parsePluginOptions(proxy.plugin_opts);
    if (obfs) {
        if (options.obfs !== undefined) { options.mode = options.obfs; delete options.obfs; }
        if (options['obfs-host'] !== undefined) { options.host = options['obfs-host']; delete options['obfs-host']; }
        if (options['obfs-uri'] !== undefined) { options.path = options['obfs-uri']; delete options['obfs-uri']; }
    }
    return { name: obfs ? 'obfs' : proxy.plugin, options };
}

export function pluginForClash(proxy) {
    const plugin = normalizePlugin(proxy);
    if (!plugin) return {};
    for (const key of ['tls', 'mux', 'skip-cert-verify']) {
        if (plugin.options[key] !== undefined) plugin.options[key] = parseBool(plugin.options[key], false);
    }
    return { plugin: plugin.name, 'plugin-opts': plugin.options };
}

export function pluginForSingbox(proxy) {
    if (!proxy.plugin) return {};
    const obfs = ['obfs', 'simple-obfs', 'obfs-local'].includes(proxy.plugin);
    const plugin = obfs ? 'obfs-local' : proxy.plugin;
    if (!['obfs-local', 'v2ray-plugin'].includes(plugin)) unsupportedProxy(proxy, 'sing-box', `unsupported plugin ${plugin}`);
    if (typeof proxy.plugin_opts === 'string') return { plugin, plugin_opts: proxy.plugin_opts };
    const options = { ...proxy.plugin_opts };
    if (obfs) {
        if (options.mode !== undefined) { options.obfs = options.mode; delete options.mode; }
        if (options.host !== undefined) { options['obfs-host'] = options.host; delete options.host; }
        if (options.path !== undefined) { options['obfs-uri'] = options.path; delete options.path; }
    }
    const escape = value => String(value).replace(/[\\;=:]/g, '\\$&');
    const plugin_opts = Object.entries(options)
        .filter(([, value]) => value !== undefined && value !== false)
        .map(([key, value]) => value === true ? escape(key) : `${escape(key)}=${escape(value)}`)
        .join(';');
    return { plugin, plugin_opts };
}

export function clashTransport(proxy) {
    const transport = proxyTransport(proxy);
    if (!transport) return { network: 'tcp' };
    switch (transport.type) {
        case 'ws':
            return {
                network: 'ws',
                'ws-opts': {
                    path: transport.path || '/',
                    headers: transport.headers,
                    ...(transport.max_early_data !== undefined ? { 'max-early-data': transport.max_early_data } : {}),
                    ...(transport.early_data_header_name ? { 'early-data-header-name': transport.early_data_header_name } : {})
                }
            };
        case 'http':
            return { network: 'h2', 'h2-opts': { host: transport.host || [], path: transport.path || '/' } };
        case 'http-obfs':
            return { network: 'http', 'http-opts': { method: transport.method || 'GET', path: parseArray(transport.path) || ['/'], headers: transport.headers } };
        case 'httpupgrade':
            if (transport.max_early_data) unsupportedProxy(proxy, 'Mihomo', 'Xray HTTPUpgrade early data cannot be represented');
            return { network: 'ws', 'ws-opts': { path: transport.path || '/', ...((transport.host || transport.headers) ? { headers: { ...transport.headers, ...(transport.host ? { Host: transport.host } : {}) } } : {}), 'v2ray-http-upgrade': true, ...(transport.fast_open ? { 'v2ray-http-upgrade-fast-open': true } : {}) } };
        case 'xhttp':
            if (proxy.type !== 'vless' || (transport.extra && Object.keys(transport.extra).length)) unsupportedProxy(proxy, 'Mihomo', 'this XHTTP protocol/extra combination is not supported');
            return { network: 'xhttp', 'xhttp-opts': { path: transport.path || '/', ...(transport.host ? { host: transport.host } : {}), mode: transport.mode || 'auto' } };
        case 'grpc':
            // Xray serves Tun alongside TunMulti, so Mihomo can use its native Tun client.
            if (transport.mode && !['gun', 'multi'].includes(transport.mode)) unsupportedProxy(proxy, 'Mihomo', `unsupported gRPC mode ${transport.mode}`);
            if (transport.authority) unsupportedProxy(proxy, 'Mihomo', 'gRPC authority cannot be represented');
            return { network: 'grpc', 'grpc-opts': { 'grpc-service-name': transport.service_name ?? '' } };
        default:
            return unsupportedProxy(proxy, 'Mihomo', `unsupported transport ${transport.type}`);
    }
}
