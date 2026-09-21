import { describe, it, expect } from 'vitest';
import { formLogicFn } from '../src/components/formLogic.js';

describe('formLogic toString fix', () => {
  it('includes parseSurgeConfigInput definition in toString output', () => {
    const fnString = formLogicFn.toString();

    // Verify the function references parseSurgeConfigInput
    expect(fnString).toContain('parseSurgeConfigInput');

    // Verify the arrow function definitions ARE included
    expect(fnString).toMatch(/(?:const|var|let)\s+parseSurgeConfigInput\s*=/);
    expect(fnString).toMatch(/(?:const|var|let)\s+parseSurgeValue\s*=/);
    expect(fnString).toMatch(/(?:const|var|let)\s+convertSurgeIniToJson\s*=/);
  });

  it('does not contain __name calls that break in browser runtime', () => {
    const fnString = formLogicFn.toString();
    // Ensure no function declarations that esbuild would inject __name() for
    expect(fnString).not.toMatch(/^\s*function\s+parseSurgeValue\b/m);
    expect(fnString).not.toMatch(/^\s*function\s+convertSurgeIniToJson\b/m);
    expect(fnString).not.toMatch(/^\s*function\s+parseSurgeConfigInput\b/m);
  });

  it('formData() returns a valid Alpine data object', () => {
    // Simulate browser global environment using Function constructor
    const fakeWindow = { APP_TRANSLATIONS: {}, PREDEFINED_RULE_SETS: {} };
    const fn = new Function('window', '(' + formLogicFn.toString() + ')(); return window;');
    const result = fn(fakeWindow);
    const data = result.formData();
    expect(typeof data.submitForm).toBe('function');
    expect(typeof data.toggleAccordion).toBe('function');
    expect(data.showAdvanced).toBe(false);
  });
});

describe('certificate verification form option', () => {
  function setup(saved = {}) {
    const storage = new Map(Object.entries(saved));
    const watchers = new Map();
    const window = { APP_TRANSLATIONS: {}, PREDEFINED_RULE_SETS: {}, location: { origin: 'https://converter.example', search: '' } };
    const localStorage = { getItem: key => storage.get(key) ?? null, setItem: (key, value) => storage.set(key, String(value)) };
    const document = { querySelector: () => null };
    const create = new Function('window', 'localStorage', 'document', 'setTimeout', `(${formLogicFn.toString()})(); return window.formData();`);
    const data = create(window, localStorage, document, () => {});
    data.$watch = (key, callback) => watchers.set(key, callback);
    data.init();
    data.input = 'trojan://password@node.example:443#Test';
    return { data, storage, watchers };
  }

  it('defaults to on and writes both choices explicitly for shared short codes', async () => {
    const { data } = setup();
    expect(data.skipCertVerify).toBe(true);
    for (const enabled of [true, false]) {
      data.skipCertVerify = enabled;
      await data.submitForm();
      const links = Object.values(data.generatedLinks).map(link => new URL(link));
      expect(links.every(link => link.searchParams.get('skip_cert_verify') === String(enabled))).toBe(true);
      expect(new Set(links.map(link => link.search)).size).toBe(1);
    }
  });

  it('preserves an explicit saved opt-out and uses the API default for older links', () => {
    const { data } = setup({ skipCertVerify: 'false' });
    expect(data.skipCertVerify).toBe(false);
    data.populateFormFromUrl(new URL('https://converter.example/clash?config=example'));
    expect(data.skipCertVerify).toBe(true);
    expect(data.showAdvanced).toBe(true);
    data.populateFormFromUrl(new URL('https://converter.example/singbox?skip_cert_verify=false'));
    expect(data.skipCertVerify).toBe(false);
    data.populateFormFromUrl(new URL('https://converter.example/singbox?skip_cert_verify=true'));
    expect(data.skipCertVerify).toBe(true);
  });

  it('persists the user-selected preference', () => {
    const { storage, watchers } = setup();
    watchers.get('skipCertVerify')(true);
    expect(storage.get('skipCertVerify')).toBe('true');
    watchers.get('skipCertVerify')(false);
    expect(storage.get('skipCertVerify')).toBe('false');
  });
});
