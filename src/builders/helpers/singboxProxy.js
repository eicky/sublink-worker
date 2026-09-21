import { deepCopy, parseBool } from '../../utils.js';
import { durationString, pluginForSingbox, portRanges, proxyTls, proxyTransport, unsupportedProxy } from './protocolOptions.js';

export function buildSingboxProxy(proxy, version = '1.12', skipCertVerify = false) {
    const minorVersion = Number(version.split('.')[1]);
    if (proxy.type === 'shadowsocksr') unsupportedProxy(proxy, 'sing-box', 'ShadowsocksR was removed in sing-box 1.6');
    if (proxy.type === 'anytls' && minorVersion < 12) unsupportedProxy(proxy, 'sing-box', 'AnyTLS requires sing-box 1.12 or newer');
    const result = deepCopy(proxy);
    const tls = proxyTls(result, skipCertVerify);
    const transport = proxyTransport(result);
    if (tls?.certificate_sha256) unsupportedProxy(proxy, 'sing-box', 'certificate fingerprint pinning is not equivalent to public-key pinning');
    if (['hysteria', 'hysteria2', 'tuic'].includes(proxy.type) && (tls?.utls?.enabled || tls?.reality?.enabled)) unsupportedProxy(proxy, 'sing-box', 'QUIC protocols do not support uTLS or REALITY');
    if (['hysteria', 'hysteria2', 'tuic', 'anytls'].includes(proxy.type) && tls?.enabled === false) unsupportedProxy(proxy, 'sing-box', 'this protocol requires TLS');
    if (transport && !['ws', 'http', 'quic', 'grpc', 'httpupgrade'].includes(transport.type)) {
        unsupportedProxy(proxy, 'sing-box', `unsupported transport ${transport.type}`);
    }
    if (transport?.type === 'grpc') {
        if (transport.mode && !['gun', 'multi'].includes(transport.mode)) unsupportedProxy(proxy, 'sing-box', `unsupported gRPC mode ${transport.mode}`);
        if (transport.authority) unsupportedProxy(proxy, 'sing-box', 'gRPC authority cannot be represented');
        // Xray exposes Tun for multi clients too; mode is not a sing-box schema field.
        delete transport.mode;
    }
    if (transport?.type === 'httpupgrade') {
        if (transport.max_early_data || transport.fast_open) unsupportedProxy(proxy, 'sing-box', 'HTTPUpgrade early data / fast open cannot be represented');
        delete transport.max_early_data;
    }
    // Some native outbounds select a TLS dialer by the block's presence, even when disabled.
    if (tls?.enabled) result.tls = tls;
    else delete result.tls;
    if (transport) result.transport = transport;
    else delete result.transport;
    if (result.network && !['tcp', 'udp'].includes(result.network) && !Array.isArray(result.network)) delete result.network;
    if (['hysteria', 'hysteria2'].includes(result.type)) {
        for (const value of [result.up_mbps ?? result.up, result.down_mbps ?? result.down]) {
            if (value !== undefined && (!Number.isSafeInteger(value) || value < 0)) unsupportedProxy(proxy, 'sing-box', 'bandwidth must be a non-negative integer in Mbps');
        }
    }
    if (proxy.udp === false && result.network === undefined) result.network = 'tcp';
    delete result.udp;
    delete result.alpn;
    if (!['vless', 'vmess'].includes(result.type)) delete result.packet_encoding;
    if (result.type !== 'vless') delete result.flow;

    switch (result.type) {
        case 'shadowsocks':
            if (result.udp_port !== undefined) unsupportedProxy(proxy, 'sing-box', 'separate Shadowsocks UDP ports cannot be represented');
            Object.assign(result, pluginForSingbox(result));
            break;
        case 'vmess':
            if (result.vmess_aead === false) unsupportedProxy(proxy, 'sing-box', 'legacy Surge VMess requires an alter-ID value that its configuration does not provide');
            delete result.vmess_aead;
            break;
        case 'vless':
            if (result.encryption && result.encryption !== 'none') unsupportedProxy(proxy, 'sing-box', 'VLESS encryption is not supported');
            delete result.encryption;
            break;
        case 'hysteria':
            if (result.protocol && result.protocol !== 'udp') unsupportedProxy(proxy, 'sing-box', `unsupported Hysteria v1 transport ${result.protocol}`);
            if (result.ports || result.server_ports) unsupportedProxy(proxy, 'sing-box', 'Hysteria v1 port hopping is not supported');
            delete result.protocol;
            delete result.fast_open;
            break;
        case 'hysteria2': {
            if (result.obfs?.type === 'gecko' && minorVersion < 14) unsupportedProxy(proxy, 'sing-box', 'Gecko obfuscation requires sing-box 1.14 or newer');
            const ranges = portRanges(result.server_ports ?? result.ports);
            if (ranges?.length) {
                result.server_ports = ranges;
                delete result.server_port;
            }
            delete result.ports;
            if (result.hop_interval !== undefined) result.hop_interval = durationString(result.hop_interval);
            if (result.hop_interval_max !== undefined) {
                if (minorVersion < 14) unsupportedProxy(proxy, 'sing-box', 'random hop intervals require sing-box 1.14 or newer');
                result.hop_interval_max = durationString(result.hop_interval_max);
            }
            if (result.up !== undefined) { result.up_mbps ??= result.up; delete result.up; }
            if (result.down !== undefined) { result.down_mbps ??= result.down; delete result.down; }
            delete result.auth;
            delete result.recv_window_conn;
            delete result.fast_open;
            break;
        }
        case 'tuic':
            if (result.ports || result.server_ports || result.hop_interval !== undefined) unsupportedProxy(proxy, 'sing-box', 'TUIC port hopping is not supported');
            if (result.token !== undefined) unsupportedProxy(proxy, 'sing-box', 'TUIC v4 token authentication is not supported');
            if (result.zero_rtt_handshake === undefined && (result.zero_rtt !== undefined || result.reduce_rtt !== undefined)) {
                result.zero_rtt_handshake = parseBool(result.reduce_rtt ?? result.zero_rtt, false);
            }
            if (result.disable_sni !== undefined) {
                result.tls = { ...result.tls, disable_sni: parseBool(result.disable_sni, false) };
            }
            if (result.heartbeat !== undefined) result.heartbeat = durationString(result.heartbeat);
            if (result.udp_over_stream && result.udp_relay_mode) unsupportedProxy(proxy, 'sing-box', 'udp_over_stream and udp_relay_mode are mutually exclusive');
            delete result.zero_rtt;
            delete result.reduce_rtt;
            delete result.disable_sni;
            delete result.fast_open;
            break;
        case 'anytls':
            if (result.client_metadata !== undefined && minorVersion < 14) unsupportedProxy(proxy, 'sing-box', 'AnyTLS client metadata requires the sing-box 1.14 target');
            if (result.disable_reuse) unsupportedProxy(proxy, 'sing-box', 'AnyTLS reuse cannot be disabled with an equivalent option');
            delete result.disable_reuse;
            for (const [source, target] of Object.entries({
                'idle-session-check-interval': 'idle_session_check_interval',
                'idle-session-timeout': 'idle_session_timeout',
                'min-idle-session': 'min_idle_session'
            })) {
                if (result[source] !== undefined) result[target] ??= result[source];
                delete result[source];
            }
            for (const key of ['idle_session_check_interval', 'idle_session_timeout']) {
                if (result[key] !== undefined) result[key] = durationString(result[key]);
            }
            break;
    }
    return result;
}
