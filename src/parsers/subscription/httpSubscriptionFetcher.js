import { decodeBase64 } from '../../utils.js';
import { parseSubscriptionContent } from './subscriptionContentParser.js';

/**
 * Decode content, trying Base64 first, then URL decoding if needed
 * @param {string} text - Raw text content
 * @returns {string} - Decoded content
 */
function decodeContent(text) {
    let decodedText;
    try {
        decodedText = decodeBase64(text.trim());
    } catch (e) {
        decodedText = text;
        if (decodedText.includes('%')) {
            try {
                decodedText = decodeURIComponent(decodedText);
            } catch (urlError) {
                console.warn('Failed to URL decode the text:', urlError);
            }
        }
    }
    return decodedText;
}

/**
 * Detect the format of subscription content
 * @param {string} content - Decoded subscription content
 * @returns {'clash'|'singbox'|'unknown'} - Detected format
 */
function detectFormat(content) {
    const trimmed = content.trim();

    // Try JSON (Sing-Box format)
    if (trimmed.startsWith('{')) {
        try {
            const parsed = JSON.parse(trimmed);
            if (parsed.outbounds || parsed.inbounds || parsed.route) {
                return 'singbox';
            }
        } catch {
            // Not valid JSON
        }
    }

    // Try YAML (Clash format) - check for proxies: key
    if (trimmed.includes('proxies:')) {
        return 'clash';
    }

    return 'unknown';
}

/**
 * Fetch subscription content from a URL and parse it
 * @param {string} url - The subscription URL to fetch
 * @param {string} userAgent - Optional User-Agent header
 * @returns {Promise<object|string[]|null>} - Parsed subscription content
 */
export async function fetchSubscription(url, userAgent) {
    console.log(`[sublink-debug] fetchSubscription(parse) url=${url} ua=${userAgent || '(none)'}`);
    try {
        const headers = new Headers();
        if (userAgent) {
            headers.set('User-Agent', userAgent);
        }
        const response = await fetch(url, {
            method: 'GET',
            headers: headers
        });
        console.log(`[sublink-debug] fetchSubscription status=${response.status} ok=${response.ok}`);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const text = await response.text();
        const decodedText = decodeContent(text);
        console.log(`[sublink-debug] fetchSubscription decoded length=${decodedText.length} prefix=${JSON.stringify(decodedText.slice(0, 200))}`);

        return parseSubscriptionContent(decodedText);
    } catch (error) {
        console.error(`[sublink-debug] fetchSubscription failed url=${url} name=${error?.name || typeof error} message=${error?.message || error}`);
        return null;
    }
}

/**
 * Fetch subscription content and detect its format without parsing
 * @param {string} url - The subscription URL to fetch
 * @param {string} userAgent - Optional User-Agent header
 * @returns {Promise<{content: string, format: 'clash'|'singbox'|'unknown', url: string, subscriptionUserinfo?: string}|null>}
 */
export async function fetchSubscriptionWithFormat(url, userAgent) {
    console.log(`[sublink-debug] fetchStart url=${url} ua=${userAgent || '(none)'}`);
    try {
        const headers = new Headers();
        if (userAgent) {
            headers.set('User-Agent', userAgent);
        }
        const response = await fetch(url, {
            method: 'GET',
            headers: headers
        });
        console.log(`[sublink-debug] fetchResp status=${response.status} ok=${response.ok} content-type=${response.headers.get('content-type') || '(none)'}`);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const text = await response.text();
        console.log(`[sublink-debug] rawText length=${text.length} prefix=${JSON.stringify(text.slice(0, 100))}`);
        const content = decodeContent(text);
        const format = detectFormat(content);
        console.log(`[sublink-debug] decoded length=${content.length} format=${format} prefix=${JSON.stringify(content.slice(0, 200))}`);

        const subscriptionUserinfo = response.headers.get('subscription-userinfo') || undefined;

        return { content, format, url, subscriptionUserinfo };
    } catch (error) {
        console.error(`[sublink-debug] fetchFailed url=${url} name=${error?.name || typeof error} message=${error?.message || error}`);
        return null;
    }
}
