import { parseShadowsocks } from './protocols/shadowsocksParser.js';
import { parseShadowsocksR } from './protocols/shadowsocksrParser.js';
import { parseVmess } from './protocols/vmessParser.js';
import { parseVless } from './protocols/vlessParser.js';
import { parseHysteria } from './protocols/hysteriaParser.js';
import { parseHysteria2 } from './protocols/hysteria2Parser.js';
import { parseTrojan } from './protocols/trojanParser.js';
import { parseTuic } from './protocols/tuicParser.js';
import { parseAnytls } from './protocols/anytlsParser.js';
import { fetchSubscription } from './subscription/httpSubscriptionFetcher.js';
import { InvalidPayloadError, ServiceError } from '../services/errors.js';

const protocolParsers = {
    ss: parseShadowsocks,
    ssr: parseShadowsocksR,
    vmess: parseVmess,
    vless: parseVless,
    hysteria: parseHysteria,
    hysteria2: parseHysteria2,
    hy2: parseHysteria2,
    http: fetchSubscription,
    https: fetchSubscription,
    trojan: parseTrojan,
    tuic: parseTuic,
    anytls: parseAnytls
};

export class ProxyParser {
    static async parse(url, userAgent) {
        if (!url || typeof url !== 'string') {
            return undefined;
        }
        const trimmed = url.trim();
        const type = trimmed.split('://')[0].toLowerCase();
        const parser = protocolParsers[type];
        if (!parser) {
            if (/^[a-z][a-z\d+.-]*:\/\//i.test(trimmed)) throw new InvalidPayloadError(`Unsupported proxy protocol: ${type}`);
            return undefined;
        }
        try {
            return await parser(trimmed, userAgent);
        } catch (error) {
            if (error instanceof ServiceError) throw error;
            throw new InvalidPayloadError(`Invalid ${type} proxy URI`);
        }
    }
}
