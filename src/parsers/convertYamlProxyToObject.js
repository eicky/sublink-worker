import { parseArray, parseBool, parseServerInfo, createEchConfig, parseCertificateSha256 } from '../utils.js';
import { InvalidPayloadError } from '../services/errors.js';

function parseTls(proxy, required = false) {
    if (!parseBool(proxy.tls, required)) return { enabled: false };
    const tls = {
        enabled: true,
        server_name: proxy.sni || proxy.servername,
        insecure: parseBool(proxy['skip-cert-verify'], false),
        ...(proxy.alpn ? { alpn: parseArray(proxy.alpn) } : {})
    };
    if (proxy['client-fingerprint'] && proxy['client-fingerprint'] !== 'none') {
        tls.utls = { enabled: true, fingerprint: proxy['client-fingerprint'] };
    }
    if (proxy['reality-opts']) {
        tls.reality = {
            enabled: true,
            public_key: proxy['reality-opts']['public-key'],
            short_id: proxy['reality-opts']['short-id'] ?? ''
        };
        tls.utls ??= { enabled: true, fingerprint: 'chrome' };
    }
    if (proxy.fingerprint) tls.certificate_sha256 = parseCertificateSha256(proxy.fingerprint);
    if (proxy['ech-opts']) {
        const ech = proxy['ech-opts'];
        tls.ech = {
            ...(ech.config ? createEchConfig(ech.config) : {}),
            enabled: parseBool(ech.enable, false),
            ...(ech['query-server-name'] ? { query_server_name: ech['query-server-name'] } : {})
        };
    }
    if (proxy['disable-sni'] !== undefined) tls.disable_sni = parseBool(proxy['disable-sni'], false);
    if (proxy.type === 'tuic') {
        tls.alpn ??= ['h3'];
        // Mihomo couples disable-sni to InsecureSkipVerify; retain the source semantics.
        if (tls.disable_sni) tls.insecure = true;
    }
    return tls;
}

function parseTransport(proxy) {
    const type = proxy.network || proxy['network-type'];
    switch (type) {
        case undefined:
        case 'tcp':
        case 'raw':
            return undefined;
        case 'ws': {
            const options = proxy['ws-opts'] || {};
            if (parseBool(options['v2ray-http-upgrade'], false)) {
                const host = Object.entries(options.headers || {}).find(([key]) => key.toLowerCase() === 'host')?.[1];
                const headers = Object.fromEntries(Object.entries(options.headers || {}).filter(([key]) => key.toLowerCase() !== 'host'));
                return {
                    type: 'httpupgrade', path: options.path || '/', ...(host ? { host } : {}),
                    ...(Object.keys(headers).length ? { headers } : {}),
                    ...(options['max-early-data'] !== undefined ? { max_early_data: options['max-early-data'] } : {}),
                    ...(parseBool(options['v2ray-http-upgrade-fast-open'], false) ? { fast_open: true } : {})
                };
            }
            return {
                type: 'ws',
                path: options.path || '/',
                ...(options.headers ? { headers: { ...options.headers } } : {}),
                ...(options['max-early-data'] !== undefined ? { max_early_data: options['max-early-data'] } : {}),
                ...(options['early-data-header-name'] ? { early_data_header_name: options['early-data-header-name'] } : {})
            };
        }
        case 'grpc': {
            const options = proxy['grpc-opts'] || {};
            return { type: 'grpc', service_name: options['grpc-service-name'] ?? '' };
        }
        case 'http': {
            const options = proxy['http-opts'] || {};
            return { type: 'http-obfs', method: options.method || 'GET', path: parseArray(options.path) || ['/'], ...(options.headers ? { headers: { ...options.headers } } : {}) };
        }
        case 'h2': {
            const options = proxy['h2-opts'] || {};
            return { type: 'http', path: options.path || '/', ...(options.host ? { host: parseArray(options.host) } : {}) };
        }
        case 'xhttp': {
            const options = proxy['xhttp-opts'] || {};
            const extra = Object.fromEntries(Object.entries(options).filter(([key]) => !['path', 'host', 'mode'].includes(key)));
            return { type, path: options.path || '/', host: options.host, mode: options.mode, ...(Object.keys(extra).length ? { extra } : {}) };
        }
        case 'httpupgrade': {
            const options = proxy['http-upgrade-opts'] || proxy['httpupgrade-opts'] || {};
            return { type, path: options.path || '/', ...(options.host ? { host: options.host } : {}) };
        }
        default:
            // Keep an unsupported transport visible to the target adapter, not as TCP.
            return { type };
    }
}

function hopIntervals(value) {
    if (value === undefined) return {};
    const match = String(value).match(/^(\d+)(?:-(\d+))?$/);
    if (!match || Number(match[1]) < 5 || (match[2] !== undefined && Number(match[2]) < Number(match[1]))) {
        throw new InvalidPayloadError('Invalid Mihomo port hopping interval');
    }
    return { hop_interval: Number(match[1]), ...(match[2] !== undefined ? { hop_interval_max: Number(match[2]) } : {}) };
}

function bandwidthMbps(value) {
    if (value === undefined || value === null || value === '') return undefined;
    if (typeof value === 'number' && Number.isFinite(value) && value >= 0) return value;
    const match = String(value).trim().match(/^(\d+(?:\.\d+)?)\s*([kmg]?)(?:bps)?$/i);
    if (!match) throw new InvalidPayloadError('Invalid protocol bandwidth');
    const multiplier = { k: 0.001, m: 1, g: 1000, '': 1 }[match[2].toLowerCase()];
    return Number(match[1]) * multiplier;
}

export function convertYamlProxyToObject(p) {
    if (!p || typeof p !== 'object' || !p.type) return null;
    const aliases = { ss: 'shadowsocks', ssr: 'shadowsocksr', hy2: 'hysteria2' };
    const sourceType = String(p.type).toLowerCase();
    const type = aliases[sourceType] || sourceType;
    if (!['shadowsocks', 'shadowsocksr', 'vmess', 'vless', 'trojan', 'hysteria', 'hysteria2', 'tuic', 'anytls'].includes(type)) return null;
    const address = String(p.server || '');
    const authority = address.includes(':') && !address.startsWith('[') ? `[${address}]` : address;
    const { host, port } = parseServerInfo(`${authority}:${p.port ?? p.server_port}`);
    const udp = parseBool(p.udp);
    const common = {
        type,
        tag: String(p.name || p.tag || `${host}:${port}`),
        server: host,
        server_port: port,
        tcp_fast_open: parseBool(p.tfo ?? p['fast-open'], false),
        ...(udp !== undefined ? { udp } : {})
    };

    switch (type) {
        case 'shadowsocks':
            return {
                ...common,
                method: p.cipher || p.method,
                password: String(p.password ?? ''),
                ...(p.plugin ? { plugin: p.plugin, plugin_opts: p['plugin-opts'] } : {})
            };
        case 'shadowsocksr':
            return {
                ...common,
                method: p.cipher || p.method,
                password: String(p.password ?? ''),
                protocol: p.protocol || 'origin',
                protocol_param: p['protocol-param'] ?? p.protocol_param,
                obfs: p.obfs || 'plain',
                obfs_param: p['obfs-param'] ?? p.obfs_param
            };
        case 'vmess':
            return {
                ...common,
                uuid: p.uuid,
                alter_id: Number(p.alterId ?? 0),
                security: p.cipher || p.security || 'auto',
                ...(p['global-padding'] !== undefined ? { global_padding: parseBool(p['global-padding'], false) } : {}),
                ...(p['authenticated-length'] !== undefined ? { authenticated_length: parseBool(p['authenticated-length'], false) } : {}),
                tls: parseTls(p),
                transport: parseTransport(p),
                ...(p['packet-encoding'] ? { packet_encoding: p['packet-encoding'] } : {})
            };
        case 'vless':
            return {
                ...common,
                uuid: p.uuid,
                tls: parseTls(p),
                transport: parseTransport(p),
                ...(p.flow ? { flow: p.flow } : {}),
                ...(p.encryption !== undefined ? { encryption: p.encryption } : {}),
                ...(p['packet-encoding'] ? { packet_encoding: p['packet-encoding'] } : {})
            };
        case 'trojan':
            return { ...common, password: String(p.password ?? ''), tls: parseTls(p, true), transport: parseTransport(p) };
        case 'hysteria':
            return {
                ...common,
                auth: p.auth,
                auth_str: p['auth-str'] ?? p.auth_str,
                obfs: p.obfs,
                up_mbps: bandwidthMbps(p.up),
                down_mbps: bandwidthMbps(p.down),
                tls: parseTls(p, true),
                ...(p.protocol && p.protocol !== 'udp' ? { protocol: p.protocol } : {}),
                ...(p['recv-window-conn'] !== undefined ? { recv_window_conn: p['recv-window-conn'] } : {}),
                ...(p['recv-window'] !== undefined ? { recv_window: p['recv-window'] } : {}),
                ...(p['disable-mtu-discovery'] !== undefined ? { disable_mtu_discovery: parseBool(p['disable-mtu-discovery'], false) } : {}),
                ...(p.ports ? { ports: p.ports } : {})
            };
        case 'hysteria2':
            return {
                ...common,
                password: String(p.password ?? ''),
                tls: parseTls(p, true),
                ...(p.obfs ? { obfs: {
                    type: p.obfs, password: p['obfs-password'],
                    ...(p['obfs-min-packet-size'] !== undefined ? { min_packet_size: p['obfs-min-packet-size'] } : {}),
                    ...(p['obfs-max-packet-size'] !== undefined ? { max_packet_size: p['obfs-max-packet-size'] } : {})
                } } : {}),
                up_mbps: bandwidthMbps(p.up),
                down_mbps: bandwidthMbps(p.down),
                ...(p.mport || p.ports ? { ports: p.mport || p.ports } : {}),
                ...hopIntervals(p['hop-interval'])
            };
        case 'tuic':
            return {
                ...common,
                ...(p.token !== undefined ? { token: p.token } : { uuid: p.uuid, password: String(p.password ?? '') }),
                congestion_control: p['congestion-controller'] || p.congestion_control || 'new_reno',
                tls: parseTls(p, true),
                ...(p['udp-relay-mode'] ? { udp_relay_mode: p['udp-relay-mode'] } : {}),
                ...(p['reduce-rtt'] !== undefined || p['zero-rtt'] !== undefined ? { zero_rtt_handshake: parseBool(p['reduce-rtt'] ?? p['zero-rtt'], false) } : {}),
                ...(p['heartbeat-interval'] !== undefined ? { heartbeat: `${p['heartbeat-interval']}ms` } : {}),
                ...(p['udp-over-stream'] !== undefined ? { udp_over_stream: parseBool(p['udp-over-stream'], false) } : {})
            };
        case 'anytls':
            return {
                ...common,
                password: String(p.password ?? ''),
                idle_session_check_interval: p['idle-session-check-interval'] ?? p.idle_session_check_interval,
                idle_session_timeout: p['idle-session-timeout'] ?? p.idle_session_timeout,
                min_idle_session: p['min-idle-session'] ?? p.min_idle_session,
                ...(p['client-metadata'] !== undefined ? { client_metadata: p['client-metadata'] } : {}),
                ...(p['disable-reuse'] !== undefined ? { disable_reuse: parseBool(p['disable-reuse'], false) } : {}),
                tls: parseTls(p, true)
            };
    }
}
