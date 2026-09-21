import { parseBool } from '../../utils.js';
import { InvalidConfigError } from '../../services/errors.js';
import { quoteSurgeValue } from '../../utils/surgeProxyLine.js';
import { durationSeconds, normalizePlugin, portRanges, proxyTls, proxyTransport, unsupportedProxy } from './protocolOptions.js';

const SS_CIPHERS = new Set([
    'none', 'rc4', 'rc4-md5', 'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb',
    'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr', 'salsa20', 'chacha20', 'chacha20-ietf',
    'aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305', 'xchacha20-ietf-poly1305',
    '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm'
]);

export function buildSurgeProxy(proxy) {
    const reject = reason => unsupportedProxy(proxy, 'Surge', reason);
    try {
        if (!['shadowsocks', 'vmess', 'trojan', 'hysteria2', 'tuic', 'anytls'].includes(proxy.type)) reject('unsupported protocol');
        if (/[=,\r\n"#;]/.test(proxy.tag)) reject('node name cannot be represented in Surge groups');
        const tls = proxyTls(proxy);
        const transport = proxyTransport(proxy);
        if (tls?.reality?.enabled) reject('REALITY is not supported');
        if (tls?.utls?.enabled) reject('uTLS fingerprints are not supported');
        if (tls?.ech?.enabled !== false && tls?.ech) reject('ECH is not supported');
        if (tls?.certificate_public_key_sha256?.length) reject('public-key pinning cannot be replaced with a certificate fingerprint');
        if (transport && (!['vmess', 'trojan'].includes(proxy.type) || transport.type !== 'ws')) reject(`unsupported transport ${transport.type}`);
        if (transport?.max_early_data) reject('WebSocket early data is not supported');
        if (['trojan', 'hysteria2', 'tuic', 'anytls'].includes(proxy.type) && tls?.enabled === false) reject('this protocol requires TLS');

        const type = proxy.type === 'shadowsocks' ? 'ss' : proxy.type === 'tuic' && proxy.token === undefined ? 'tuic-v5' : proxy.type;
        const ranges = portRanges(proxy.server_ports ?? proxy.ports, '-');
        const primaryPort = proxy.server_port ?? Number(ranges?.[0]?.split('-')[0]);
        const fields = [type, quoteSurgeValue(proxy.server), primaryPort];
        const add = (key, value) => { if (value !== undefined && value !== null) fields.push(`${key}=${quoteSurgeValue(value)}`); };

        switch (proxy.type) {
            case 'shadowsocks': {
                if (!SS_CIPHERS.has(proxy.method)) reject(`unsupported Shadowsocks cipher ${proxy.method}`);
                add('encrypt-method', proxy.method);
                add('password', proxy.password);
                add('udp-relay', parseBool(proxy.udp, proxy.network !== 'tcp'));
                add('udp-port', proxy.udp_port);
                const plugin = normalizePlugin(proxy);
                if (plugin) {
                    if (plugin.name !== 'obfs') reject(`unsupported plugin ${plugin.name}`);
                    const options = plugin.options;
                    if (!['http', 'tls'].includes(options.mode) || Object.keys(options).some(key => !['mode', 'host', 'path'].includes(key))) reject('unsupported simple-obfs options');
                    add('obfs', options.mode);
                    add('obfs-host', options.host);
                    add('obfs-uri', options.path);
                }
                break;
            }
            case 'vmess': {
                if (proxy.alter_id > 0) reject('legacy VMess alter IDs cannot be represented');
                if (proxy.global_padding || proxy.authenticated_length) reject('VMess padding/length options cannot be represented');
                const cipher = { auto: 'aes-128-gcm', 'aes-128-gcm': 'aes-128-gcm', 'chacha20-poly1305': 'chacha20-ietf-poly1305' }[proxy.security || 'auto'];
                if (!cipher) reject(`unsupported VMess cipher ${proxy.security}`);
                add('username', proxy.uuid);
                add('encrypt-method', cipher);
                add('vmess-aead', proxy.vmess_aead ?? true);
                add('tls', tls?.enabled ?? false);
                break;
            }
            case 'trojan':
                add('password', proxy.password);
                break;
            case 'hysteria2':
                if (proxy.up_mbps || proxy.up) reject('Hysteria2 upload bandwidth cannot be represented');
                if (proxy.hop_interval_max !== undefined) reject('random port-hopping intervals cannot be represented');
                add('password', proxy.password);
                add('download-bandwidth', proxy.down_mbps ?? proxy.down);
                if (proxy.obfs) {
                    if (!['salamander', 'gecko'].includes(proxy.obfs.type)) reject('unsupported Hysteria2 obfuscation');
                    if (proxy.obfs.min_packet_size !== undefined || proxy.obfs.max_packet_size !== undefined) reject('Gecko packet-size options cannot be represented');
                    add(`${proxy.obfs.type}-password`, proxy.obfs.password);
                }
                break;
            case 'tuic':
                if (proxy.congestion_control || proxy.zero_rtt_handshake || proxy.heartbeat !== undefined || proxy.udp_over_stream || (proxy.udp_relay_mode && proxy.udp_relay_mode !== 'native')) reject('TUIC congestion/0-RTT/heartbeat/UDP tuning cannot be represented');
                if (proxy.token !== undefined) add('token', proxy.token);
                else { add('uuid', proxy.uuid); add('password', proxy.password); }
                break;
            case 'anytls':
                if (['idle_session_check_interval', 'idle_session_timeout', 'min_idle_session', 'idle-session-check-interval', 'idle-session-timeout', 'min-idle-session', 'client_metadata'].some(key => proxy[key] !== undefined)) reject('AnyTLS session/metadata options cannot be represented by the reuse flag');
                add('password', proxy.password);
                if (proxy.disable_reuse !== undefined) add('reuse', !proxy.disable_reuse);
                break;
        }

        if (tls?.enabled) {
            add('sni', tls.disable_sni ? 'off' : tls.server_name);
            if (tls.disable_sni && tls.server_name) add('server-cert-verify-name', tls.server_name);
            add('skip-cert-verify', parseBool(tls.insecure, false));
            if (tls.alpn !== undefined) {
                if (!tls.alpn.length && ['tuic', 'hysteria2'].includes(proxy.type)) reject('an empty ALPN cannot be replaced by the Surge h3 default');
                if (tls.alpn.length) add('alpn', tls.alpn.join(','));
            }
            add('server-cert-fingerprint-sha256', tls.certificate_sha256);
        }
        if (transport) {
            add('ws', true);
            add('ws-path', transport.path || '/');
            const headers = Object.entries(transport.headers || {}).map(([key, value]) => {
                if (Array.isArray(value) || /[:|\r\n]/.test(key) || /[|\r\n]/.test(String(value))) reject('WebSocket headers cannot be represented');
                return `${key.toLowerCase() === 'host' ? 'Host' : key}:${value}`;
            });
            if (headers.length) add('ws-headers', headers.join('|'));
        }
        if (ranges?.length) {
            if (!['hysteria2', 'tuic'].includes(proxy.type)) reject('port hopping is not supported for this protocol');
            add('port-hopping', ranges.join(';'));
        }
        if (proxy.hop_interval !== undefined) {
            const seconds = durationSeconds(proxy.hop_interval);
            if (!Number.isInteger(seconds) || seconds < 5) reject('port-hopping interval must be whole seconds, at least 5');
            add('port-hopping-interval', seconds);
        }
        add('tfo', proxy.tcp_fast_open);
        return `${proxy.tag} = ${fields.join(', ')}`;
    } catch (error) {
        if (!(error instanceof InvalidConfigError)) throw error;
        const tag = String(proxy.tag || proxy.type).replace(/[\r\n]/g, ' ');
        return `# ${tag} - Unsupported: ${error.message.replace(/[\r\n]/g, ' ')}`;
    }
}
