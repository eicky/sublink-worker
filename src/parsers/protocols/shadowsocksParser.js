import { base64ToBinary, decodeBase64, parseServerInfo, parseUrlParams } from '../../utils.js';
import { InvalidPayloadError } from '../../services/errors.js';

const AEAD_2022_KEY_LENGTHS = {
    '2022-blake3-aes-128-gcm': 16,
    '2022-blake3-aes-256-gcm': 32,
    '2022-blake3-chacha20-poly1305': 32,
    '2022-blake3-chacha12-poly1305': 32,
    '2022-blake3-chacha8-poly1305': 32
};

function splitMethodAndPassword(value) {
    const separator = value.indexOf(':');
    if (separator <= 0) {
        throw new Error('Invalid Shadowsocks userinfo');
    }
    return [value.slice(0, separator), value.slice(separator + 1)];
}

function parseUserInfo(userInfo) {
    if (userInfo.includes(':')) {
        const [method, password] = splitMethodAndPassword(userInfo);
        return [decodeURIComponent(method), decodeURIComponent(password)];
    }
    const credentials = splitMethodAndPassword(decodeBase64(decodeURIComponent(userInfo)));
    if (credentials[0].startsWith('2022-blake3-')) {
        throw new Error('AEAD-2022 userinfo must not be Base64URL-encoded');
    }
    return credentials;
}

function validateCredentials(method, password) {
    if (!method || !password) {
        throw new Error('Shadowsocks method and password are required');
    }
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(method)) {
        throw new Error('Invalid Shadowsocks method');
    }

    if (!method.startsWith('2022-blake3-')) {
        return;
    }

    const expectedLength = AEAD_2022_KEY_LENGTHS[method];
    if (!expectedLength) {
        throw new Error(`Unsupported AEAD-2022 method: ${method}`);
    }
    for (const key of password.split(':')) {
        if (!/^[A-Za-z0-9+/]+={0,2}$/.test(key) || base64ToBinary(key).length !== expectedLength) {
            throw new Error(`Invalid ${method} key`);
        }
    }
}

function splitEscaped(value, separator) {
    const parts = [];
    let current = '';
    let escaped = false;

    for (const character of value) {
        if (escaped) {
            current += `\\${character}`;
            escaped = false;
        } else if (character === '\\') {
            escaped = true;
        } else if (character === separator) {
            parts.push(current);
            current = '';
        } else {
            current += character;
        }
    }
    if (escaped) {
        throw new Error('Invalid escaped plugin option');
    }
    parts.push(current);
    return parts;
}

function findUnescaped(value, separator) {
    let escaped = false;
    for (let index = 0; index < value.length; index++) {
        const character = value[index];
        if (escaped) {
            escaped = false;
        } else if (character === '\\') {
            escaped = true;
        } else if (character === separator) {
            return index;
        }
    }
    return -1;
}

function unescapePluginValue(value) {
    return value.replace(/\\(.)/gs, '$1');
}

/**
 * Parse plugin string from URL query parameter
 * Format: "simple-obfs;obfs=http;obfs-host=example.com" or "v2ray-plugin;mode=websocket;host=example.com"
 * @param {string} pluginStr - The plugin parameter value (URL decoded)
 * @returns {{plugin: string, plugin_opts: object}|null} - Parsed plugin info or null
 */
function parsePluginString(pluginStr) {
    if (!pluginStr) return null;

    const parts = splitEscaped(pluginStr, ';');
    const pluginName = unescapePluginValue(parts[0]);

    if (!pluginName) return null;

    const opts = {};
    for (let i = 1; i < parts.length; i++) {
        const eqIndex = findUnescaped(parts[i], '=');
        if (eqIndex === -1) {
            // Boolean flag without value (e.g., "tls")
            const key = unescapePluginValue(parts[i]).trim();
            if (key) {
                opts[key] = true;
            }
            continue;
        }
        const key = unescapePluginValue(parts[i].substring(0, eqIndex));
        const value = unescapePluginValue(parts[i].substring(eqIndex + 1));
        if (key) {
            opts[key] = value;
        }
    }

    return {
        plugin: pluginName,
        plugin_opts: Object.keys(opts).length > 0 ? opts : undefined
    };
}

function createConfig(tag, server, serverPort, method, password, pluginInfo) {
    validateCredentials(method, password);
    const displayServer = server.includes(':') ? `[${server}]` : server;
    const config = {
        tag: tag || `${displayServer}:${serverPort}`,
        type: 'shadowsocks',
        server,
        server_port: serverPort,
        method,
        password,
        tcp_fast_open: false
    };

    // Add plugin fields if present
    if (pluginInfo) {
        config.plugin = pluginInfo.plugin;
        if (pluginInfo.plugin_opts) {
            config.plugin_opts = pluginInfo.plugin_opts;
        }
    }

    return config;
}

export function parseShadowsocks(url) {
    try {
        const normalizedUrl = typeof url === 'string' ? url.trim() : '';
        if (!/^ss:\/\//i.test(normalizedUrl)) {
            throw new Error('Invalid Shadowsocks URI scheme');
        }

        const { addressPart, params, name } = parseUrlParams(normalizedUrl);
        const hasPlugin = Object.hasOwn(params, 'plugin');
        const pluginInfo = hasPlugin ? parsePluginString(params.plugin) : null;
        if (hasPlugin && !pluginInfo) {
            throw new Error('Shadowsocks plugin name is required');
        }
        const serverSeparator = addressPart.lastIndexOf('@');

        if (serverSeparator < 0) {
            const decodedLegacy = decodeBase64(decodeURIComponent(addressPart));
            const legacyServerSeparator = decodedLegacy.lastIndexOf('@');
            if (legacyServerSeparator <= 0) {
                throw new Error('Invalid legacy Shadowsocks URL');
            }
            const [method, password] = splitMethodAndPassword(decodedLegacy.slice(0, legacyServerSeparator));
            if (method.startsWith('2022-blake3-')) {
                throw new Error('AEAD-2022 credentials must use plain SIP002 userinfo');
            }
            const { host, port } = parseServerInfo(decodedLegacy.slice(legacyServerSeparator + 1));
            return createConfig(name, host, port, method, password, pluginInfo);
        }

        const [method, password] = parseUserInfo(addressPart.slice(0, serverSeparator));
        const { host, port } = parseServerInfo(addressPart.slice(serverSeparator + 1));
        return createConfig(name, host, port, method, password, pluginInfo);
    } catch (error) {
        if (error instanceof InvalidPayloadError) throw error;
        throw new InvalidPayloadError('Invalid Shadowsocks URI');
    }
}
