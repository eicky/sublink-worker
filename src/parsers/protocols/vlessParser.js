import { parseProxyUri, createTlsConfig, createTransportConfig, parseBool } from '../../utils.js';

export function parseVless(url) {
    const { userinfo, host, port, params, name } = parseProxyUri(url);
    const tls = createTlsConfig({ ...params, sni: params.sni || params.peer || host, fp: params.fp || 'chrome' });
    const transport = createTransportConfig(params);
    const udp = parseBool(params.udp);

    return {
        type: 'vless',
        tag: name,
        server: host,
        server_port: port,
        uuid: decodeURIComponent(userinfo),
        tcp_fast_open: parseBool(params.tfo, false),
        tls,
        transport,
        ...(params.flow ? { flow: params.flow } : {}),
        ...(params.encryption !== undefined ? { encryption: params.encryption } : {}),
        ...(params.packetEncoding ? { packet_encoding: params.packetEncoding } : {}),
        ...(udp !== undefined ? { udp } : {})
    };
}
