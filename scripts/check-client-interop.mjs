import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, X509Certificate } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import http from 'node:http';
import http2 from 'node:http2';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { parseArgs } from 'node:util';
import { ProxyParser } from '../src/parsers/ProxyParser.js';
import { ClashConfigBuilder } from '../src/builders/ClashConfigBuilder.js';
import { SingboxConfigBuilder } from '../src/builders/SingboxConfigBuilder.js';

const { values } = parseArgs({ options: { mihomo: { type: 'string' }, 'sing-box': { type: 'string' }, xray: { type: 'string' }, openssl: { type: 'string', default: 'openssl' }, only: { type: 'string' } } });
if ((!values.mihomo && !values['sing-box']) || !values.xray) {
    console.error('Usage: node scripts/check-client-interop.mjs --xray /path/to/xray [--mihomo /path/to/mihomo] [--sing-box /path/to/sing-box] [--openssl /path/to/openssl]');
    process.exit(1);
}

const directory = await mkdtemp(join(tmpdir(), 'sublink-client-interop-'));
const uuid = 'd342d11e-d424-4583-b36e-524ab1f0afa4';
const password = 'interop-test-password';
const payload = `sublink-interop-${randomBytes(16).toString('hex')}`;
const origin = http.createServer((_request, response) => response.end(payload));
let cover;
let passed = 0;

function listen(server) {
    return new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(0, '127.0.0.1', () => {
            server.removeListener('error', reject);
            resolve(server.address().port);
        });
    });
}

async function freePort() {
    const server = net.createServer();
    const port = await listen(server);
    await new Promise(resolve => server.close(resolve));
    return port;
}

function startCore(executable, args) {
    const child = spawn(resolve(executable), args, { stdio: ['ignore', 'pipe', 'pipe'] });
    const core = { process: child, log: '', error: null };
    child.stdout.on('data', data => { core.log += data; });
    child.stderr.on('data', data => { core.log += data; });
    child.on('error', error => { core.error = error; });
    return core;
}

async function waitForPort(core, port) {
    const deadline = Date.now() + 10000;
    while (Date.now() < deadline) {
        if (core.error) throw core.error;
        if (core.process.exitCode !== null) throw new Error(core.log || 'Core exited before listening');
        const ready = await new Promise(resolve => {
            const socket = net.connect({ host: '127.0.0.1', port });
            socket.once('connect', () => { socket.destroy(); resolve(true); });
            socket.once('error', () => resolve(false));
        });
        if (ready) return;
        await delay(25);
    }
    throw new Error(`Core did not listen on its loopback port: ${core.log}`);
}

async function stopCore(core) {
    if (!core || core.process.exitCode !== null || core.process.signalCode !== null || core.error) return;
    await new Promise(resolve => {
        core.process.once('exit', resolve);
        core.process.kill();
    });
}

function requestThroughProxy(proxyPort, originPort) {
    return new Promise((resolve, reject) => {
        const request = http.get({
            hostname: '127.0.0.1', port: proxyPort,
            path: `http://127.0.0.1:${originPort}/interop`,
            headers: { Host: `127.0.0.1:${originPort}` },
            agent: false
        }, response => {
            let body = '';
            response.setEncoding('utf8');
            response.on('data', data => { body += data; });
            response.on('error', reject);
            response.on('end', () => resolve({ status: response.statusCode, body }));
        });
        request.setTimeout(5000, () => request.destroy(new Error('Proxy request timed out')));
        request.on('error', reject);
    });
}

try {
    const certFile = join(directory, 'certificate.pem');
    const keyFile = join(directory, 'private-key.pem');
    const certificate = spawnSync(values.openssl, ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyFile, '-out', certFile, '-days', '1', '-subj', '/CN=node.example', '-addext', 'subjectAltName=DNS:node.example'], { encoding: 'utf8', timeout: 20000 });
    if (certificate.error) throw certificate.error;
    assert.equal(certificate.status, 0, certificate.stderr);
    const cert = await readFile(certFile);
    const key = await readFile(keyFile);
    const fingerprint = new X509Certificate(cert).fingerprint256.replaceAll(':', '').toLowerCase();
    const { privateKey, publicKey } = generateKeyPairSync('x25519');
    const realityPrivateKey = privateKey.export({ format: 'jwk' }).d;
    const realityPublicKey = publicKey.export({ format: 'jwk' }).x;
    const originPort = await listen(origin);
    cover = http2.createSecureServer({ cert, key, minVersion: 'TLSv1.3', allowHTTP1: true }, (_request, response) => response.end('local-cover'));
    const coverPort = await listen(cover);

    const cases = [
        { name: 'vless-plain-tcp', protocol: 'vless', security: 'none', transport: 'tcp' },
        { name: 'vless-grpc-multi-server-gun', protocol: 'vless', serverMulti: false },
        { name: 'vless-grpc-multi-server-multi', protocol: 'vless', serverMulti: true },
        { name: 'vmess-grpc-multi', protocol: 'vmess', serverMulti: true },
        { name: 'trojan-grpc-multi', protocol: 'trojan', serverMulti: true },
        { name: 'vless-grpc-multi-reality', protocol: 'vless', serverMulti: true, reality: true },
        { name: 'vless-tls-certificate-pin', protocol: 'vless', pin: fingerprint },
        { name: 'vless-tls-wrong-certificate-pin', protocol: 'vless', pin: '00'.repeat(32), reject: true },
        { name: 'vless-tls-skip-verification', protocol: 'vless', pin: '00'.repeat(32), skipCertVerify: true },
        { name: 'vless-tls-untrusted-certificate', protocol: 'vless', transport: 'tcp', untrusted: true, reject: true },
        { name: 'vless-plain-tcp-skip-verification', protocol: 'vless', security: 'none', transport: 'tcp', skipCertVerify: true },
        { name: 'vless-grpc-multi-reality-skip-verification', protocol: 'vless', serverMulti: true, reality: true, skipCertVerify: true }
    ];
    const clients = ['mihomo', 'sing-box'].filter(client => values[client]);

    for (const test of cases.filter(test => !values.only || test.name === values.only).flatMap(test => clients.map(client => ({ ...test, client })))) {
        const label = `${test.client}/${test.name}`;
        const builder = test.client === 'mihomo'
            ? new ClashConfigBuilder('', [], [], null, 'en', null, false, false, undefined, undefined, true, test.skipCertVerify)
            : new SingboxConfigBuilder('', [], [], null, 'en', null, false, false, undefined, undefined, '1.14', true, test.skipCertVerify);
        if (test.client === 'sing-box' && test.pin && !test.skipCertVerify) {
            const parsed = await ProxyParser.parse(`vless://${uuid}@127.0.0.1:443?security=tls&pcs=${test.pin}#interop`);
            assert.throws(() => builder.convertProxy(parsed), /certificate fingerprint pinning/);
            console.log(`PASS ${label}: unrepresentable certificate pin explicitly rejected`);
            passed++;
            continue;
        }
        let xray;
        let clientCore;
        try {
            const xrayPort = await freePort();
            const proxyPort = await freePort();
            const credentials = test.protocol === 'trojan' ? { password } : { id: uuid };
            const settings = { clients: [credentials], ...(test.protocol === 'vless' ? { decryption: 'none' } : {}) };
            const transport = test.transport || (test.pin ? 'tcp' : 'grpc');
            const security = test.security || (test.reality ? 'reality' : 'tls');
            const streamSettings = {
                network: transport,
                security,
                ...(transport === 'grpc' ? { grpcSettings: { serviceName: 'sublink-interop', multiMode: test.serverMulti } } : {}),
                ...(security === 'reality' ? {
                    realitySettings: { dest: `127.0.0.1:${coverPort}`, serverNames: ['node.example'], privateKey: realityPrivateKey, shortIds: ['abcd'] }
                } : security === 'tls' ? {
                    tlsSettings: { certificates: [{ certificateFile: certFile, keyFile }], alpn: ['h2', 'http/1.1'] }
                } : {})
            };
            const xrayConfig = { log: { loglevel: 'warning' }, inbounds: [{ listen: '127.0.0.1', port: xrayPort, protocol: test.protocol, settings, streamSettings }], outbounds: [{ protocol: 'freedom' }] };
            const xrayFile = join(directory, 'xray.json');
            await writeFile(xrayFile, JSON.stringify(xrayConfig));
            xray = startCore(values.xray, ['run', '-config', xrayFile]);
            await waitForPort(xray, xrayPort);

            const params = new URLSearchParams({ security, type: transport });
            if (security !== 'none') params.set('sni', 'node.example');
            if (test.reality) {
                params.set('pbk', realityPublicKey);
                params.set('sid', 'abcd');
                params.set('fp', 'chrome');
            } else if (security === 'tls' && !test.untrusted && (test.client === 'mihomo' || test.pin)) {
                params.set('pcs', test.pin || fingerprint);
            }
            if (transport === 'grpc') {
                params.set('serviceName', 'sublink-interop');
                params.set('mode', 'multi');
            }
            const uri = `${test.protocol}://${test.protocol === 'trojan' ? password : uuid}@127.0.0.1:${xrayPort}?${params}#interop`;
            const proxy = builder.convertProxy(await ProxyParser.parse(uri));
            let config;
            if (test.client === 'mihomo') {
                if (security !== 'none') assert.equal(proxy['skip-cert-verify'], Boolean(test.skipCertVerify && !test.reality));
                if (test.skipCertVerify) assert.ok(!Object.hasOwn(proxy, 'fingerprint'));
                config = { 'mixed-port': proxyPort, 'bind-address': '127.0.0.1', 'allow-lan': false, mode: 'rule', 'log-level': 'warning', proxies: [proxy], rules: ['MATCH,interop'] };
            } else {
                if (security !== 'none') assert.equal(proxy.tls.insecure, Boolean(test.skipCertVerify && !test.reality));
                if (test.skipCertVerify) assert.ok(!Object.hasOwn(proxy.tls || {}, 'certificate_sha256'));
                // Default interoperability cases trust the fixture CA; opt-in cases must work without it.
                if (security === 'tls' && !test.untrusted && !test.skipCertVerify) proxy.tls.certificate = cert.toString('utf8').trim().split('\n');
                config = { log: { level: 'warn' }, inbounds: [{ type: 'mixed', listen: '127.0.0.1', listen_port: proxyPort }], outbounds: [proxy], route: { final: 'interop' } };
            }
            const clientFile = join(directory, `${test.client}.json`);
            await writeFile(clientFile, JSON.stringify(config));
            const args = test.client === 'mihomo' ? ['-f', clientFile, '-d', directory] : ['run', '-c', clientFile, '-D', directory];
            clientCore = startCore(values[test.client], args);
            await waitForPort(clientCore, proxyPort);
            const response = await requestThroughProxy(proxyPort, originPort).catch(error => ({ error }));
            if (test.reject) {
                assert.notEqual(response.body, payload, 'A mismatched certificate must never reach the origin');
                assert.match(clientCore.log, test.pin ? /fingerprint/i : /certificate|x509/i, 'The failure must be caused by certificate verification');
            } else {
                assert.equal(response.status, 200, `Proxy request failed: ${response.error?.message || response.body}\n${clientCore.log}\n${xray.log}`);
                assert.equal(response.body, payload, 'The response must come through the configured proxy');
            }
            console.log(`PASS ${label}${test.reject ? ': certificate mismatch rejected' : ': loopback HTTP round trip'}`);
            passed++;
        } finally {
            await stopCore(clientCore);
            await stopCore(xray);
        }
    }
} finally {
    origin.closeAllConnections();
    origin.close();
    cover?.close();
    await rm(directory, { recursive: true, force: true });
}
assert.ok(passed, 'No matching interoperability cases');
console.log(`Client/Xray interoperability: ${passed} passed`);
