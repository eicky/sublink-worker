import { parseProxyUri, createTlsConfig, createTransportConfig, parseBool } from '../../utils.js';

export function parseTrojan(url) {
    const { userinfo, host, port, params, name } = parseProxyUri(url);
    const tls = createTlsConfig({ ...params, security: params.security ?? 'tls' });
    const udp = parseBool(params.udp);

    return {
        type: 'trojan',
        tag: name,
        server: host,
        server_port: port,
        password: decodeURIComponent(userinfo),
        tcp_fast_open: parseBool(params.tfo, false),
        tls,
        transport: createTransportConfig(params),
        ...(udp !== undefined ? { udp } : {})
    };
}
