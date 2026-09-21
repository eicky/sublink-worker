import { parseBool } from '../../utils.js';
import { clashTransport, clashEch, durationSeconds, pluginForClash, portRanges, proxyTls, proxyTransport, unsupportedProxy } from './protocolOptions.js';

export function buildClashProxy(proxy, skipCertVerify = false) {
    const base = { name: proxy.tag, type: proxy.type, server: proxy.server, port: proxy.server_port };
    const tls = proxyTls(proxy, skipCertVerify);
    const networks = Array.isArray(proxy.network) ? proxy.network : proxy.network ? [proxy.network] : [];
    if (networks.includes('udp') && !networks.includes('tcp')) unsupportedProxy(proxy, 'Mihomo', 'UDP-only network restrictions cannot be represented');
    const udp = parseBool(proxy.udp, networks.length ? networks.includes('udp') : true);
    const tlsFields = tls?.enabled ? {
        'skip-cert-verify': parseBool(tls.insecure, false),
        ...(tls.alpn !== undefined ? { alpn: tls.alpn } : {}),
        ...(tls.utls?.enabled && tls.utls.fingerprint ? { 'client-fingerprint': tls.utls.fingerprint } : {}),
        ...(tls.reality?.enabled ? { 'reality-opts': { 'public-key': tls.reality.public_key, 'short-id': tls.reality.short_id ?? '' } } : {}),
        ...(tls.certificate_sha256 ? { fingerprint: tls.certificate_sha256 } : {}),
        ...(tls.ech ? { 'ech-opts': clashEch(proxy, tls.ech) } : {})
    } : {};
    if (tls?.certificate_public_key_sha256?.length) unsupportedProxy(proxy, 'Mihomo', 'public-key pinning cannot be replaced with a certificate fingerprint');
    if (['hysteria', 'hysteria2', 'tuic'].includes(proxy.type) && (tls?.utls?.enabled || tls?.reality?.enabled)) unsupportedProxy(proxy, 'Mihomo', 'QUIC protocols do not support uTLS or REALITY');
    if (tls?.disable_sni && proxy.type !== 'tuic') unsupportedProxy(proxy, 'Mihomo', 'disabling SNI cannot be represented for this protocol');
    if (['trojan', 'hysteria', 'hysteria2', 'tuic', 'anytls'].includes(proxy.type) && tls?.enabled === false) {
        unsupportedProxy(proxy, 'Mihomo', 'this protocol requires TLS');
    }

    switch (proxy.type) {
        case 'shadowsocks':
            if (proxy.udp_port !== undefined) unsupportedProxy(proxy, 'Mihomo', 'separate Shadowsocks UDP ports cannot be represented');
            return { ...base, type: 'ss', cipher: proxy.method, password: proxy.password, udp, tfo: proxy.tcp_fast_open, ...pluginForClash(proxy) };
        case 'shadowsocksr':
            return {
                ...base, type: 'ssr', cipher: proxy.method, password: proxy.password, udp,
                protocol: proxy.protocol, 'protocol-param': proxy.protocol_param,
                obfs: proxy.obfs, 'obfs-param': proxy.obfs_param
            };
        case 'vmess':
            if (proxy.vmess_aead === false) unsupportedProxy(proxy, 'Mihomo', 'legacy Surge VMess requires an alter-ID value that its configuration does not provide');
            return {
                ...base, uuid: proxy.uuid, alterId: proxy.alter_id ?? 0, cipher: proxy.security || 'auto',
                ...(proxy.global_padding !== undefined ? { 'global-padding': proxy.global_padding } : {}),
                ...(proxy.authenticated_length !== undefined ? { 'authenticated-length': proxy.authenticated_length } : {}),
                tls: tls?.enabled ?? false, servername: tls?.server_name, ...tlsFields,
                ...clashTransport(proxy), udp, tfo: proxy.tcp_fast_open,
                ...(proxy.packet_encoding ? { 'packet-encoding': proxy.packet_encoding } : {})
            };
        case 'vless':
            return {
                ...base, uuid: proxy.uuid, tls: tls?.enabled ?? false, servername: tls?.server_name,
                ...(proxy.encryption ? { encryption: proxy.encryption } : {}),
                ...tlsFields, ...clashTransport(proxy), udp, tfo: proxy.tcp_fast_open,
                ...(proxy.flow ? { flow: proxy.flow } : {}),
                ...(proxy.packet_encoding ? { 'packet-encoding': proxy.packet_encoding } : {})
            };
        case 'trojan':
            if (proxyTransport(proxy) && !['ws', 'grpc', 'httpupgrade'].includes(proxyTransport(proxy).type)) unsupportedProxy(proxy, 'Mihomo', 'Trojan only supports TCP, WebSocket/HTTPUpgrade and gRPC');
            return {
                ...base, password: proxy.password, sni: tls?.server_name, ...tlsFields,
                ...clashTransport(proxy), udp, tfo: proxy.tcp_fast_open
            };
        case 'hysteria':
            return {
                ...base, 'auth-str': proxy.auth_str, auth: proxy.auth,
                up: proxy.up_mbps ?? proxy.up, down: proxy.down_mbps ?? proxy.down,
                obfs: proxy.obfs, protocol: proxy.protocol,
                sni: tls?.server_name, ...tlsFields,
                'recv-window-conn': proxy.recv_window_conn, 'recv-window': proxy.recv_window,
                'disable-mtu-discovery': proxy.disable_mtu_discovery,
                ...(proxy.ports ? { ports: portRanges(proxy.ports, '-').join(',') } : {})
            };
        case 'hysteria2': {
            const ranges = portRanges(proxy.server_ports ?? proxy.ports, '-');
            if (ranges?.length > 28) unsupportedProxy(proxy, 'Mihomo', 'port hopping accepts at most 28 ranges');
            const interval = durationSeconds(proxy.hop_interval);
            const maximum = durationSeconds(proxy.hop_interval_max);
            if ((interval !== undefined && (!Number.isInteger(interval) || interval < 5)) ||
                (maximum !== undefined && (!Number.isInteger(maximum) || interval === undefined || maximum < interval))) {
                unsupportedProxy(proxy, 'Mihomo', 'hop intervals require whole seconds, at least 5, with an ordered minimum and maximum');
            }
            return {
                ...base, port: base.port ?? Number(ranges?.[0]?.split('-')[0]), password: proxy.password,
                ...(ranges?.length ? { ports: ranges.join(',') } : {}),
                ...(proxy.obfs ? {
                    obfs: proxy.obfs.type, 'obfs-password': proxy.obfs.password,
                    ...(proxy.obfs.min_packet_size !== undefined ? { 'obfs-min-packet-size': proxy.obfs.min_packet_size } : {}),
                    ...(proxy.obfs.max_packet_size !== undefined ? { 'obfs-max-packet-size': proxy.obfs.max_packet_size } : {})
                } : {}),
                up: proxy.up_mbps ?? proxy.up, down: proxy.down_mbps ?? proxy.down,
                sni: tls?.server_name, ...tlsFields,
                ...(interval !== undefined ? { 'hop-interval': maximum === undefined ? interval : `${interval}-${maximum}` } : {})
            };
        }
        case 'tuic': {
            if (proxy.ports || proxy.server_ports || proxy.hop_interval !== undefined) unsupportedProxy(proxy, 'Mihomo', 'TUIC port hopping is not supported');
            const disableSni = parseBool(tls?.disable_sni ?? proxy.disable_sni, false);
            if (disableSni && !parseBool(tls?.insecure, false)) unsupportedProxy(proxy, 'Mihomo', 'disable_sni also disables certificate verification in this client');
            const reduceRtt = proxy.zero_rtt_handshake ?? proxy.reduce_rtt ?? proxy.zero_rtt;
            return {
                ...base,
                ...(proxy.token !== undefined ? { token: proxy.token } : { uuid: proxy.uuid, password: proxy.password }),
                'congestion-controller': proxy.congestion_control ?? 'cubic',
                sni: tls?.server_name, ...tlsFields, alpn: tls?.alpn ?? [],
                ...(tls?.disable_sni !== undefined || proxy.disable_sni !== undefined ? { 'disable-sni': tls?.disable_sni ?? proxy.disable_sni } : {}),
                ...(proxy.udp_relay_mode ? { 'udp-relay-mode': proxy.udp_relay_mode } : {}),
                ...(reduceRtt !== undefined ? { [proxy.token !== undefined ? 'zero-rtt' : 'reduce-rtt']: parseBool(reduceRtt, false) } : {}),
                ...(proxy.heartbeat !== undefined ? { 'heartbeat-interval': durationSeconds(proxy.heartbeat) * 1000 } : {}),
                ...(proxy.udp_over_stream !== undefined ? { 'udp-over-stream': proxy.udp_over_stream } : {})
            };
        }
        case 'anytls': {
            if (tls?.reality?.enabled) unsupportedProxy(proxy, 'Mihomo', 'AnyTLS does not support REALITY');
            const interval = proxy.idle_session_check_interval ?? proxy['idle-session-check-interval'];
            const timeout = proxy.idle_session_timeout ?? proxy['idle-session-timeout'];
            const minimum = proxy.min_idle_session ?? proxy['min-idle-session'];
            for (const duration of [interval, timeout]) {
                if (duration !== undefined && !Number.isInteger(durationSeconds(duration))) unsupportedProxy(proxy, 'Mihomo', 'AnyTLS session durations require whole seconds');
            }
            return {
                ...base, password: proxy.password, sni: tls?.server_name, ...tlsFields, udp,
                ...(proxy.client_metadata !== undefined ? { 'client-metadata': proxy.client_metadata } : {}),
                ...(proxy.disable_reuse !== undefined ? { 'disable-reuse': proxy.disable_reuse } : {}),
                ...(interval !== undefined ? { 'idle-session-check-interval': durationSeconds(interval) } : {}),
                ...(timeout !== undefined ? { 'idle-session-timeout': durationSeconds(timeout) } : {}),
                ...(minimum !== undefined ? { 'min-idle-session': minimum } : {})
            };
        }
        default:
            return unsupportedProxy(proxy, 'Mihomo', 'unsupported protocol');
    }
}
