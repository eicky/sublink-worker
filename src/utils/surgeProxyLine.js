import { InvalidPayloadError, InvalidConfigError } from '../services/errors.js';

export function splitSurgeFields(text) {
    const fields = [];
    let field = '', quoted = false;
    for (const char of text) {
        if (char === '"') quoted = !quoted;
        if (char === ',' && !quoted) {
            fields.push(field.trim());
            field = '';
        } else {
            field += char;
        }
    }
    if (quoted) throw new InvalidPayloadError('Unterminated quoted Surge value');
    fields.push(field.trim());
    return fields;
}

export function parseSurgeValue(value) {
    const text = value.trim();
    const unquoted = text.startsWith('"') && text.endsWith('"') ? text.slice(1, -1) : text;
    if (unquoted.includes('"')) throw new InvalidPayloadError('Unsupported quote in Surge value');
    return unquoted;
}

export function quoteSurgeValue(value) {
    const text = String(value);
    // Surge documents quoted comma lists, but no portable nested-quote escape syntax.
    if (/["\\\r\n]/.test(text)) throw new InvalidConfigError('Surge cannot safely represent this quote or escape character');
    return /[,#]/.test(text) || text.trim() !== text ? `"${text}"` : text;
}
