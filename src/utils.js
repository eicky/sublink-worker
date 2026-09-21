import { InvalidPayloadError } from './services/errors.js';

const PATH_LENGTH = 7;
const FNV_32_OFFSET_BASIS = 0x811c9dc5;
const FNV_32_PRIME = 0x01000193;

// 自定义的字符串前缀检查函数
export function checkStartsWith(str, prefix) {
	if (str === undefined || str === null || prefix === undefined || prefix === null) {
		return false;
	}
	str = String(str);
	prefix = String(prefix);
	return str.slice(0, prefix.length) === prefix;
}


// Base64 编码函数
export function encodeBase64(input) {
	const encoder = new TextEncoder();
	const utf8Array = encoder.encode(input);
	let binaryString = '';
	for (const byte of utf8Array) {
		binaryString += String.fromCharCode(byte);
	}
	return base64FromBinary(binaryString);
}

// Base64 解码函数
export function decodeBase64(input) {
	const binaryString = base64ToBinary(input);
	const bytes = new Uint8Array(binaryString.length);
	for (let i = 0; i < binaryString.length; i++) {
		bytes[i] = binaryString.charCodeAt(i);
	}
	const decoder = new TextDecoder();
	return decoder.decode(bytes);
}

// 将二进制字符串转换为 Base64（编码）
export function base64FromBinary(binaryString) {
	const base64Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
	let base64String = '';
	let padding = '';

	const remainder = binaryString.length % 3;
	if (remainder > 0) {
		padding = '='.repeat(3 - remainder);
		binaryString += '\0'.repeat(3 - remainder);
	}

	for (let i = 0; i < binaryString.length; i += 3) {
		const bytes = [
			binaryString.charCodeAt(i),
			binaryString.charCodeAt(i + 1),
			binaryString.charCodeAt(i + 2)
		];
		const base64Index1 = bytes[0] >> 2;
		const base64Index2 = ((bytes[0] & 3) << 4) | (bytes[1] >> 4);
		const base64Index3 = ((bytes[1] & 15) << 2) | (bytes[2] >> 6);
		const base64Index4 = bytes[2] & 63;

		base64String += base64Chars[base64Index1] +
			base64Chars[base64Index2] +
			base64Chars[base64Index3] +
			base64Chars[base64Index4];
	}

	return base64String.slice(0, base64String.length - padding.length) + padding;
}

// 将 Base64 转换为二进制字符串（解码）
export function base64ToBinary(base64String) {
	if (typeof base64String !== 'string') {
		throw new InvalidPayloadError('Invalid Base64 value');
	}
	const normalized = base64String.replace(/\s/g, '').replace(/-/g, '+').replace(/_/g, '/');
	if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalized) || normalized.length % 4 === 1) {
		throw new InvalidPayloadError('Invalid Base64 value');
	}
	try {
		// Share links commonly omit padding; atob still rejects misplaced padding.
		const padded = normalized.includes('=') ? normalized : normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
		return atob(padded);
	} catch (_) {
		throw new InvalidPayloadError('Invalid Base64 value');
	}
}

export function tryDecodeSubscriptionLines(input, { decodeUriComponent = false } = {}) {
	if (typeof input !== 'string') {
		return input;
	}

	const trimmed = input.trim();
	if (trimmed === '') {
		return trimmed;
	}

	const splitIfMultiple = (value) => {
		if (typeof value !== 'string') {
			return value;
		}

		const normalized = value.replace(/\r\n/g, '\n');
		const segments = normalized
			.split('\n')
			.map(segment => segment.trim())
			.filter(segment => segment !== '');

		if (segments.length > 1 && segments.some(segment => segment.includes('://'))) {
			return segments;
		}

		return normalized.trim();
	};

	const directResult = splitIfMultiple(trimmed);
	if (Array.isArray(directResult)) {
		return directResult;
	}
	if (typeof directResult === 'string' && directResult.includes('://')) {
		return directResult;
	}

	try {
		let decoded = decodeBase64(trimmed);
		if (decodeUriComponent && decoded.includes('%')) {
			const hasProtocolScheme = decoded.includes('://');
			if (!hasProtocolScheme) {
				try {
					decoded = decodeURIComponent(decoded);
				} catch (_) {
					// ignore URI decode errors and fall back to the decoded string
				}
			}
		}

		const decodedResult = splitIfMultiple(decoded);
		if (Array.isArray(decodedResult)) {
			return decodedResult;
		}
		if (typeof decodedResult === 'string' && decodedResult.includes('://')) {
			return decodedResult;
		}
	} catch (_) {
		// ignore decoding errors and return the original trimmed input
	}

	return trimmed;
}

export function groupProxiesByCountry(proxies, { getName } = {}) {
	const extractor = typeof getName === 'function'
		? getName
		: (proxy) => {
			if (proxy == null) return undefined;
			if (typeof proxy === 'string') {
				return proxy;
			}
			if (typeof proxy === 'object') {
				return proxy.name ?? proxy.tag ?? proxy.id ?? proxy.ps;
			}
			return undefined;
		};

	const normalizeName = (value) => {
		if (typeof value !== 'string') {
			return undefined;
		}
		const trimmed = value.trim();
		if (!trimmed) {
			return undefined;
		}
		const eqIndex = trimmed.indexOf('=');
		if (eqIndex > -1) {
			const beforeEq = trimmed.slice(0, eqIndex).trim();
			if (beforeEq) {
				return beforeEq;
			}
		}
		return trimmed;
	};

	const grouped = {};
	if (!Array.isArray(proxies) || proxies.length === 0) {
		return grouped;
	}

	proxies.forEach(proxy => {
		const rawName = extractor(proxy);
		const proxyName = normalizeName(rawName);
		if (!proxyName) {
			return;
		}
		const countryInfo = parseCountryFromNodeName(proxyName);
		if (!countryInfo) {
			return;
		}
		const { name } = countryInfo;
		if (!grouped[name]) {
			grouped[name] = { ...countryInfo, proxies: [] };
		}
		grouped[name].proxies.push(proxyName);
	});

	return grouped;
}

export function createStableProviderName(url) {
	if (typeof url !== 'string' || url.trim() === '') {
		throw new Error('Provider URL must be a non-empty string');
	}

	const normalizedUrl = url.trim();
	let hash = FNV_32_OFFSET_BASIS;
	for (let i = 0; i < normalizedUrl.length; i++) {
		hash ^= normalizedUrl.charCodeAt(i);
		hash = Math.imul(hash, FNV_32_PRIME);
	}

	return `_auto_provider_${(hash >>> 0).toString(36)}`;
}

export function deepCopy(obj) {
	if (obj === null || typeof obj !== 'object') {
		return obj;
	}
	if (Array.isArray(obj)) {
		return obj.map(item => deepCopy(item));
	}
	const newObj = {};
	for (const key in obj) {
		if (Object.prototype.hasOwnProperty.call(obj, key)) {
			newObj[key] = deepCopy(obj[key]);
		}
	}
	return newObj;
}

export function generateWebPath(length = PATH_LENGTH) {
	const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
	let result = ''
	for (let i = 0; i < length; i++) {
		result += characters.charAt(Math.floor(Math.random() * characters.length))
	}
	return result
}

export function parseServerInfo(serverInfo, defaultPort) {
	if (typeof serverInfo !== 'string' || !serverInfo) {
		throw new InvalidPayloadError('Missing proxy server');
	}
	const authority = serverInfo.replace(/\/$/, '');
	let host, port;
	if (authority.startsWith('[')) {
		const match = authority.match(/^\[([^\]]+)\](?::([^:]*))?$/);
		if (!match || !match[1].includes(':')) {
			throw new InvalidPayloadError('Invalid bracketed IPv6 address');
		}
		[, host, port] = match;
		try {
			new URL(`http://[${host}]/`);
		} catch (_) {
			throw new InvalidPayloadError('Invalid IPv6 address');
		}
	} else {
		const parts = authority.split(':');
		if (parts.length > 2) {
			throw new InvalidPayloadError('IPv6 addresses must be enclosed in brackets');
		}
		[host, port] = parts;
	}
	if (!host || /[\s\/@?#\[\]]/.test(host)) {
		throw new InvalidPayloadError('Invalid proxy server');
	}
	const portValue = port === undefined ? defaultPort : port;
	if (!/^\d+$/.test(String(portValue)) || Number(portValue) < 1 || Number(portValue) > 65535) {
		throw new InvalidPayloadError('Proxy port must be an integer between 1 and 65535');
	}
	return { host, port: Number(portValue) };
}

export function parseUrlParams(url) {
	if (typeof url !== 'string' || !/^[a-z][a-z\d+.-]*:\/\//i.test(url)) {
		throw new InvalidPayloadError('Invalid proxy URI scheme');
	}
	const rest = url.slice(url.indexOf('://') + 3);
	const hashIndex = rest.indexOf('#');
	const beforeFragment = hashIndex < 0 ? rest : rest.slice(0, hashIndex);
	if (/%(?![\da-f]{2})/i.test(beforeFragment)) throw new InvalidPayloadError('Invalid URI percent encoding');
	let name = hashIndex < 0 ? '' : rest.slice(hashIndex + 1);
	const queryIndex = beforeFragment.indexOf('?');
	const addressPart = queryIndex < 0 ? beforeFragment : beforeFragment.slice(0, queryIndex);
	const searchParams = new URLSearchParams(queryIndex < 0 ? '' : beforeFragment.slice(queryIndex + 1));
	const seen = new Set();
	for (const key of searchParams.keys()) {
		if (seen.has(key)) throw new InvalidPayloadError(`Duplicate URI parameter: ${key}`);
		seen.add(key);
	}
	try {
		name = decodeURIComponent(name);
	} catch (_) {
		// A literal percent in a display name must not corrupt the credentials.
	}
	return { addressPart, params: Object.fromEntries(searchParams), name };
}

export function parseProxyUri(url, defaultPort, { requireUserinfo = true } = {}) {
	const { addressPart, params, name } = parseUrlParams(url);
	const atIndex = addressPart.lastIndexOf('@');
	if (requireUserinfo && atIndex <= 0) {
		throw new InvalidPayloadError('Proxy URI is missing credentials');
	}
	const { host, port } = parseServerInfo(addressPart.slice(atIndex + 1), defaultPort);
	return {
		userinfo: atIndex < 0 ? '' : addressPart.slice(0, atIndex),
		host, port, params,
		fragmentName: name,
		name: name || `${host}:${port}`
	};
}

export function parseCertificateSha256(value, name = 'certificate fingerprint') {
	if (value === undefined) return undefined;
	const normalized = String(value).trim().toLowerCase().replace(/[:-]/g, '');
	if (!/^[a-f0-9]{64}$/.test(normalized)) throw new InvalidPayloadError(`Invalid ${name}: expected a SHA-256 certificate fingerprint`);
	return normalized;
}

export function createEchConfig(value) {
	if (typeof value !== 'string' || !value) throw new InvalidPayloadError('ECH config must be Base64');
	const base64 = base64FromBinary(base64ToBinary(value));
	return { enabled: true, config: ['-----BEGIN ECH CONFIGS-----', base64, '-----END ECH CONFIGS-----'] };
}

export function createTlsConfig(params = {}) {
	const security = params.security ?? 'none';
	const certificatePin = params.pcs?.trim();
	if (certificatePin && security !== 'tls') throw new InvalidPayloadError('TLS pcs certificate pinning requires security=tls');
	if (security === 'none') return { enabled: false };
	if (security !== 'tls' && security !== 'reality') {
		throw new InvalidPayloadError(`Unsupported TLS security: ${security}`);
	}
	for (const option of ['ech', 'vcn', 'pqv', 'spx']) {
		if (params[option]) throw new InvalidPayloadError(`Unsupported TLS share-link option: ${option}`);
	}
	const tls = {
		enabled: true,
		server_name: params.sni || params.peer || params.host || undefined,
		insecure: parseBoolParam(params.allowInsecure ?? params.insecure ?? params.allow_insecure ?? params['skip-cert-verify'], { fallback: false, name: 'TLS insecure flag' })
	};
	if (certificatePin) tls.certificate_sha256 = parseCertificateSha256(certificatePin, 'TLS pcs');
	const alpn = parseArray(params.alpn);
	if (alpn?.length) tls.alpn = alpn;
	const fingerprint = params.fp || params['client-fingerprint'] || (security === 'reality' ? 'chrome' : undefined);
	if (fingerprint && fingerprint !== 'none') {
		tls.utls = { enabled: true, fingerprint };
	}
	if (security === 'reality') {
		if (!params.pbk) throw new InvalidPayloadError('REALITY requires a public key (pbk)');
		tls.reality = { enabled: true, public_key: params.pbk, short_id: params.sid ?? '' };
	}
	return tls;
}

function transportPath(path, type) {
	const queryIndex = path.indexOf('?');
	const fragmentIndex = path.indexOf('#');
	if (queryIndex < 0 || (fragmentIndex >= 0 && fragmentIndex < queryIndex)) return { path };
	const query = new URLSearchParams(path.slice(queryIndex + 1, fragmentIndex < 0 ? undefined : fragmentIndex));
	const earlyData = query.get('ed');
	if (earlyData === null || earlyData === '') return { path };
	if (!/^\d+$/.test(earlyData) || Number(earlyData) > 8192 || query.getAll('ed').length > 1) {
		throw new InvalidPayloadError('Invalid transport early-data size');
	}
	// Xray consumes ed locally; it is not part of the server's request path.
	query.delete('ed');
	const suffix = query.toString();
	return {
		path: path.slice(0, queryIndex) + (suffix ? `?${suffix}` : '') + (fragmentIndex < 0 ? '' : path.slice(fragmentIndex)),
		max_early_data: Number(earlyData),
		...(type === 'ws' ? { early_data_header_name: 'Sec-WebSocket-Protocol' } : {})
	};
}

export function createTransportConfig(params = {}) {
	if (params.fm) throw new InvalidPayloadError('FinalMask transport settings cannot be converted');
	const type = params.type || 'tcp';
	if (type === 'tcp' || type === 'raw') {
		if (params.headerType === 'http') {
			return { type: 'http-obfs', path: parseArray(params.path) || ['/'], ...(params.host ? { headers: { Host: parseArray(params.host) } } : {}) };
		}
		return undefined;
	}
	const path = params.path || '/';
	switch (type) {
		case 'ws':
			return { type, ...transportPath(path, type), ...(params.host ? { headers: { Host: params.host } } : {}) };
		case 'http':
		case 'h2':
			return { type: 'http', ...(params.host ? { host: parseArray(params.host) } : {}), path };
		case 'httpupgrade':
			return { type, ...(params.host ? { host: params.host } : {}), ...transportPath(path, type) };
		case 'quic':
			return { type };
		case 'grpc':
			return {
				type,
				service_name: params.serviceName ?? '',
				...(params.mode && params.mode !== 'gun' ? { mode: params.mode } : {}),
				...(params.authority ? { authority: params.authority } : {})
			};
		case 'xhttp': {
			let extra;
			if (params.extra) {
				try { extra = JSON.parse(params.extra); } catch (_) { throw new InvalidPayloadError('Invalid XHTTP extra JSON'); }
			}
			return { type, path, ...(params.host ? { host: params.host } : {}), ...(params.mode ? { mode: params.mode } : {}), ...(extra ? { extra } : {}) };
		}
		default:
			throw new InvalidPayloadError(`Unsupported transport: ${type}`);
	}
}

export function getUniqueParamAlias(params, keys, name) {
	const present = keys.filter(key => params[key] !== undefined);
	if (present.length > 1) throw new InvalidPayloadError(`Duplicate ${name} parameters`);
	return present.length === 1 ? params[present[0]] : undefined;
}

export function parseBoolParam(value, { fallback, name = 'boolean parameter', values = ['0', '1', 'true', 'false'] } = {}) {
	if (value === undefined || value === null) return fallback;
	const text = String(value).trim().toLowerCase();
	if (!values.map(value => String(value).toLowerCase()).includes(text)) {
		throw new InvalidPayloadError(`Invalid ${name}: expected a boolean value`);
	}
	const parsed = parseBool(value);
	if (parsed === undefined) throw new InvalidPayloadError(`Invalid ${name}: expected a boolean value`);
	return parsed;
}

// Parse boolean value from various formats
export function parseBool(value, fallback = undefined) {
	if (value === undefined || value === null) return fallback;
	if (typeof value === 'boolean') return value;
	const lowered = String(value).trim().toLowerCase();
	if (lowered === 'true' || lowered === '1') return true;
	if (lowered === 'false' || lowered === '0') return false;
	return fallback;
}

// Parse comma-separated string to array
export function parseArray(value) {
	if (!value) return undefined;
	if (Array.isArray(value)) return value;
	return String(value)
		.split(',')
		.map(entry => entry.trim())
		.filter(entry => entry.length > 0);
}

export const COUNTRY_DATA = {
	'HK': { name: 'Hong Kong', emoji: '🇭🇰', aliases: ['香港', 'Hong Kong', 'HK'] },
	'TW': { name: 'Taiwan', emoji: '🇹🇼', aliases: ['台湾', 'Taiwan', 'TW'] },
	'JP': { name: 'Japan', emoji: '🇯🇵', aliases: ['日本', 'Japan', 'JP'] },
	'KR': { name: 'Korea', emoji: '🇰🇷', aliases: ['韩国', 'Korea', 'KR'] },
	'SG': { name: 'Singapore', emoji: '🇸🇬', aliases: ['新加坡', 'Singapore', 'SG'] },
	'US': { name: 'United States', emoji: '🇺🇸', aliases: ['美国', 'United States', 'US'] },
	'GB': { name: 'United Kingdom', emoji: '🇬🇧', aliases: ['英国', 'United Kingdom', 'UK', 'GB'] },
	'DE': { name: 'Germany', emoji: '🇩🇪', aliases: ['德国', 'Germany'] },
	'FR': { name: 'France', emoji: '🇫🇷', aliases: ['法国', 'France'] },
	'RU': { name: 'Russia', emoji: '🇷🇺', aliases: ['俄罗斯', 'Russia'] },
	'CA': { name: 'Canada', emoji: '🇨🇦', aliases: ['加拿大', 'Canada'] },
	'AU': { name: 'Australia', emoji: '🇦🇺', aliases: ['澳大利亚', 'Australia'] },
	'IN': { name: 'India', emoji: '🇮🇳', aliases: ['印度', 'India'] },
	'BR': { name: 'Brazil', emoji: '🇧🇷', aliases: ['巴西', 'Brazil'] },
	'ZA': { name: 'South Africa', emoji: '🇿🇦', aliases: ['南非', 'South Africa'] },
	'AR': { name: 'Argentina', emoji: '🇦🇷', aliases: ['阿根廷', 'Argentina'] },
	'TR': { name: 'Turkey', emoji: '🇹🇷', aliases: ['土耳其', 'Turkey'] },
	'NL': { name: 'Netherlands', emoji: '🇳🇱', aliases: ['荷兰', 'Netherlands'] },
	'CH': { name: 'Switzerland', emoji: '🇨🇭', aliases: ['瑞士', 'Switzerland'] },
	'SE': { name: 'Sweden', emoji: '🇸🇪', aliases: ['瑞典', 'Sweden'] },
	'IT': { name: 'Italy', emoji: '🇮🇹', aliases: ['意大利', 'Italy'] },
	'ES': { name: 'Spain', emoji: '🇪🇸', aliases: ['西班牙', 'Spain'] },
	'IE': { name: 'Ireland', emoji: '🇮🇪', aliases: ['爱尔兰', 'Ireland'] },
	'MY': { name: 'Malaysia', emoji: '🇲🇾', aliases: ['马来西亚', 'Malaysia'] },
	'TH': { name: 'Thailand', emoji: '🇹🇭', aliases: ['泰国', 'Thailand'] },
	'VN': { name: 'Vietnam', emoji: '🇻🇳', aliases: ['越南', 'Vietnam'] },
	'PH': { name: 'Philippines', emoji: '🇵🇭', aliases: ['菲律宾', 'Philippines'] },
	'ID': { name: 'Indonesia', emoji: '🇮🇩', aliases: ['印度尼西亚', 'Indonesia'] },
	'NZ': { name: 'New Zealand', emoji: '🇳🇿', aliases: ['新西兰', 'New Zealand'] },
	'AE': { name: 'United Arab Emirates', emoji: '🇦🇪', aliases: ['阿联酋', 'United Arab Emirates'] },
};

export function parseCountryFromNodeName(nodeName) {
	// Build patterns sorted by length descending so longer aliases match first
	// (e.g. "Indonesia" before "India", "United States" before "US").
	// Short aliases (<=3 chars, all ASCII, e.g. US, UK, HK) get \b word boundaries
	// to prevent false positives like "plus" matching "US".
	const allEntries = Object.values(COUNTRY_DATA).flatMap(c =>
		c.aliases.map(alias => ({ alias, escaped: alias.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&') }))
	);
	allEntries.sort((a, b) => b.alias.length - a.alias.length);

	const patterns = allEntries.map(({ alias, escaped }) => {
		if (alias.length <= 3 && /^[A-Za-z]+$/.test(alias)) {
			return `\\b${escaped}\\b`;
		}
		return escaped;
	});

	const regex = new RegExp(patterns.join('|'), 'i');
	const match = nodeName.match(regex);

	if (match) {
		const matchedAlias = match[0];
		for (const code in COUNTRY_DATA) {
			if (COUNTRY_DATA[code].aliases.some(alias => alias.toLowerCase() === matchedAlias.toLowerCase())) {
				return { code, ...COUNTRY_DATA[code] };
			}
		}
	}

	return null;
}

// Build a mihomo proxy-group `filter` regex matching node names of one country.
// Mirrors the classification patterns in parseCountryFromNodeName (same escaping
// and \b rules) so runtime filtering agrees with build-time grouping; the flag
// emoji is added because mihomo filters raw names, which often carry it.
export function buildCountryNameFilter({ emoji, aliases } = {}) {
	const patterns = (aliases || []).map(alias => {
		const escaped = alias.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&');
		if (alias.length <= 3 && /^[A-Za-z]+$/.test(alias)) {
			return `\\b${escaped}\\b`;
		}
		return escaped;
	});
	if (emoji) {
		patterns.push(emoji);
	}
	if (patterns.length === 0) {
		return null;
	}
	return `(?i)${patterns.join('|')}`;
}
