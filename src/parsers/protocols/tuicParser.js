import { createTlsConfig, getUniqueParamAlias, parseBoolParam, parseProxyUri } from '../../utils.js';
import { InvalidPayloadError } from '../../services/errors.js';

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const CONGESTION_CONTROLS = new Set(['cubic', 'new_reno', 'bbr']);
const UDP_RELAY_MODES = new Set(['native', 'quic']);

function parseScheme(url) {
    if (typeof url !== 'string' || !/^tuic:\/\//i.test(url)) {
        throw new InvalidPayloadError('Invalid TUIC URI scheme');
    }
}

function decodeCredential(value, name) {
    try {
        return decodeURIComponent(value);
    } catch (_) {
        throw new InvalidPayloadError(`Invalid TUIC ${name} encoding`);
    }
}

function parseCredentials(userinfo) {
    const separator = userinfo.indexOf(':');
    if (separator < 0) {
        throw new InvalidPayloadError('TUIC v5 URI credentials must contain UUID and password; v4 token links are unsupported');
    }
    const rawPassword = userinfo.slice(separator + 1);
    if (userinfo.includes('@') || rawPassword.includes(':')) {
        throw new InvalidPayloadError('TUIC password must percent-encode reserved delimiters');
    }
    const uuid = decodeCredential(userinfo.slice(0, separator), 'UUID');
    const password = decodeCredential(rawPassword, 'password');
    if (!UUID_PATTERN.test(uuid)) {
        throw new InvalidPayloadError('Invalid TUIC UUID');
    }
    return { uuid, password };
}

function parseCongestionControl(value) {
    if (value === undefined) return 'cubic';
    const normalized = String(value).toLowerCase() === 'newreno'
        ? 'new_reno'
        : String(value).toLowerCase();
    if (!CONGESTION_CONTROLS.has(normalized)) {
        throw new InvalidPayloadError(`Unsupported TUIC congestion control: ${value}`);
    }
    return normalized;
}

function parseUdpRelayMode(value) {
    if (value === undefined) return 'native';
    const normalized = String(value).toLowerCase();
    if (!UDP_RELAY_MODES.has(normalized)) {
        throw new InvalidPayloadError(`Unsupported TUIC UDP relay mode: ${value}`);
    }
    return normalized;
}

function parseHeartbeat(params) {
    const duration = getUniqueParamAlias(params, ['heartbeat'], 'TUIC heartbeat');
    const milliseconds = getUniqueParamAlias(params, ['heartbeat-interval', 'heartbeat_interval'], 'TUIC heartbeat interval');
    if (duration !== undefined && milliseconds !== undefined) {
        throw new InvalidPayloadError('Duplicate TUIC heartbeat parameters');
    }
    if (milliseconds !== undefined) {
        const value = Number(milliseconds);
        if (!/^\d+$/.test(String(milliseconds)) || !Number.isSafeInteger(value) || value <= 0) {
            throw new InvalidPayloadError('TUIC heartbeat interval must be a positive number of milliseconds');
        }
        return `${value}ms`;
    }
    if (duration === undefined) return undefined;

    const normalized = /^\d+(?:\.\d+)?$/.test(String(duration)) ? `${duration}s` : String(duration);
    const pattern = /^(?:\d+(?:\.\d+)?(?:ns|us|µs|ms|s|m|h))+$/;
    if (!pattern.test(normalized)) throw new InvalidPayloadError('Invalid TUIC heartbeat duration');
    const millisecondsPerUnit = { ns: 1e-6, us: 0.001, 'µs': 0.001, ms: 1, s: 1000, m: 60000, h: 3600000 };
    const totalMilliseconds = [...normalized.matchAll(/(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)/g)]
        .reduce((total, match) => total + Number(match[1]) * millisecondsPerUnit[match[2]], 0);
    if (!Number.isSafeInteger(totalMilliseconds) || totalMilliseconds <= 0) {
        throw new InvalidPayloadError('TUIC heartbeat duration must resolve to whole milliseconds');
    }
    return normalized;
}

export function parseTuic(url) {
    parseScheme(url);
    const { userinfo, host, port, params, fragmentName } = parseProxyUri(url);
    const credentials = parseCredentials(userinfo);
    if (params.security !== undefined && params.security !== 'tls') {
        throw new InvalidPayloadError(`Unsupported TUIC TLS mode: ${params.security}`);
    }
    if (params.ech !== undefined || params.pbk !== undefined || params.sid !== undefined) {
        throw new InvalidPayloadError('TUIC ECH and REALITY URI extensions are not supported');
    }

    const congestionControl = parseCongestionControl(
        getUniqueParamAlias(params, ['congestion_control', 'congestion-controller'], 'TUIC congestion control')
    );
    const udpRelayMode = parseUdpRelayMode(
        getUniqueParamAlias(params, ['udp_relay_mode', 'udp-relay-mode'], 'TUIC UDP relay mode')
    );
    const zeroRtt = parseBoolParam(
        getUniqueParamAlias(params, ['zero_rtt_handshake', 'zero-rtt', 'zero_rtt', 'reduce-rtt', 'reduce_rtt'], 'TUIC 0-RTT'),
        { fallback: undefined, name: 'TUIC 0-RTT flag' }
    );
    const insecure = parseBoolParam(
        getUniqueParamAlias(params, ['allow_insecure', 'allowInsecure', 'insecure', 'skip-cert-verify'], 'TUIC insecure TLS'),
        { fallback: false, name: 'TUIC insecure flag' }
    );
    const disableSni = parseBoolParam(
        getUniqueParamAlias(params, ['disable_sni', 'disable-sni'], 'TUIC disable SNI'),
        { fallback: undefined, name: 'TUIC disable SNI flag' }
    );
    const serverName = getUniqueParamAlias(params, ['sni', 'server_name', 'servername'], 'TUIC server name');
    const tls = createTlsConfig({
        security: 'tls',
        sni: serverName,
        insecure,
        alpn: params.alpn
    });
    tls.alpn ??= [];
    if (disableSni !== undefined) tls.disable_sni = disableSni;

    const heartbeat = parseHeartbeat(params);
    const displayHost = host.includes(':') ? `[${host}]` : host;
    const defaultName = `${displayHost}:${port}`;
    return {
        tag: fragmentName || defaultName,
        type: 'tuic',
        server: host,
        server_port: port,
        ...credentials,
        congestion_control: congestionControl,
        udp_relay_mode: udpRelayMode,
        ...(zeroRtt !== undefined ? { zero_rtt_handshake: zeroRtt } : {}),
        ...(heartbeat !== undefined ? { heartbeat } : {}),
        tls
    };
}
