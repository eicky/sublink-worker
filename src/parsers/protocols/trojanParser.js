import { parseServerInfo, parseUrlParams, createTlsConfig, createTransportConfig } from '../../utils.js';

export function parseTrojan(url) {
    const { addressPart, params, name } = parseUrlParams(url);
    const [password, serverInfo] = addressPart.split('@');
    const { host, port } = parseServerInfo(serverInfo);

    // Trojan requires TLS by default - enable unless explicitly disabled
    const effectiveParams = {
        ...params,
        security: params.security || 'tls'
    };

    const tls = createTlsConfig(effectiveParams);
    // Only create transport if type is explicitly specified and not 'tcp'
    const transport = params.type && params.type !== 'tcp' ? createTransportConfig(params) : undefined;

    return {
        type: 'trojan',
        tag: name,
        server: host,
        server_port: port,
        password: decodeURIComponent(password),
        network: 'tcp',
        tcp_fast_open: false,
        tls,
        transport,
        flow: params.flow ?? undefined
    };
}
