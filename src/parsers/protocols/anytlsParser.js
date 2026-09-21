import { createTlsConfig, getUniqueParamAlias, parseBoolParam, parseCertificateSha256, parseProxyUri } from '../../utils.js';
import { InvalidPayloadError } from '../../services/errors.js';

function parseNonNegativeInteger(value, name, suffix = '') {
    if (value === undefined) return undefined;
    const errorMessage = `AnyTLS ${name} must be a non-negative integer${suffix}`;
    if (!/^\d+$/.test(String(value))) {
        throw new InvalidPayloadError(errorMessage);
    }
    const result = Number(value);
    if (!Number.isSafeInteger(result)) {
        throw new InvalidPayloadError(errorMessage);
    }
    return result;
}

function decodePassword(userinfo) {
    if (userinfo.includes('@') || userinfo.includes(':')) {
        throw new InvalidPayloadError('AnyTLS password must percent-encode reserved delimiters');
    }
    try {
        return decodeURIComponent(userinfo);
    } catch (_) {
        throw new InvalidPayloadError('Invalid AnyTLS password encoding');
    }
}

export function parseAnytls(url) {
    if (typeof url !== 'string' || !/^anytls:\/\//i.test(url)) {
        throw new InvalidPayloadError('Invalid AnyTLS URI scheme');
    }

    const { userinfo, host, port, params, fragmentName } = parseProxyUri(url, 443, { requireUserinfo: false });
    const password = decodePassword(userinfo);
    if (params.security !== undefined && params.security !== 'tls') {
        throw new InvalidPayloadError(`Unsupported AnyTLS TLS mode: ${params.security}`);
    }
    if (params.ech !== undefined || params.pbk !== undefined || params.sid !== undefined) {
        throw new InvalidPayloadError('AnyTLS ECH and REALITY URI extensions are not supported');
    }
    const unsupportedMaximum = getUniqueParamAlias(params, ['max-idle-session', 'max_idle_session'], 'AnyTLS maximum idle session');
    if (unsupportedMaximum !== undefined) {
        throw new InvalidPayloadError('AnyTLS max idle session is not supported by the protocol or target clients');
    }

    const insecure = parseBoolParam(
        getUniqueParamAlias(params, ['insecure', 'skip-cert-verify', 'allowInsecure', 'allow_insecure'], 'AnyTLS insecure TLS'),
        { fallback: false, name: 'AnyTLS insecure flag' }
    );
    const serverName = getUniqueParamAlias(params, ['sni', 'servername', 'host'], 'AnyTLS server name');
    const clientFingerprint = getUniqueParamAlias(params, ['fp', 'client-fingerprint'], 'AnyTLS client fingerprint');
    const tls = createTlsConfig({
        security: 'tls',
        sni: serverName,
        insecure,
        alpn: params.alpn,
        fp: clientFingerprint
    });
    const certificateSha256 = parseCertificateSha256(params.fingerprint, 'AnyTLS fingerprint');
    if (certificateSha256) tls.certificate_sha256 = certificateSha256;

    const udp = parseBoolParam(params.udp, { fallback: undefined, name: 'AnyTLS UDP flag' });
    const idleSessionCheckInterval = parseNonNegativeInteger(
        getUniqueParamAlias(params, ['idle-session-check-interval', 'idle_session_check_interval'], 'AnyTLS idle session check interval'),
        'idle-session-check-interval',
        ' number of seconds'
    );
    const idleSessionTimeout = parseNonNegativeInteger(
        getUniqueParamAlias(params, ['idle-session-timeout', 'idle_session_timeout'], 'AnyTLS idle session timeout'),
        'idle-session-timeout',
        ' number of seconds'
    );
    const minIdleSession = parseNonNegativeInteger(
        getUniqueParamAlias(params, ['min-idle-session', 'min_idle_session'], 'AnyTLS minimum idle session'),
        'min-idle-session'
    );

    const displayHost = host.includes(':') ? `[${host}]` : host;
    return {
        tag: fragmentName || `AnyTLS ${displayHost}:${port}`,
        type: 'anytls',
        server: host,
        server_port: port,
        password,
        ...(udp !== undefined ? { udp } : {}),
        ...(idleSessionCheckInterval !== undefined ? { idle_session_check_interval: idleSessionCheckInterval } : {}),
        ...(idleSessionTimeout !== undefined ? { idle_session_timeout: idleSessionTimeout } : {}),
        ...(minIdleSession !== undefined ? { min_idle_session: minIdleSession } : {}),
        tls
    };
}
