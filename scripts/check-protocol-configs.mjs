import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { parseArgs } from 'node:util';
import { ProxyParser } from '../src/parsers/ProxyParser.js';
import { SingboxConfigBuilder } from '../src/builders/SingboxConfigBuilder.js';
import { ClashConfigBuilder } from '../src/builders/ClashConfigBuilder.js';

const { values } = parseArgs({ options: { 'sing-box': { type: 'string' }, mihomo: { type: 'string' }, only: { type: 'string' } } });
if (!values['sing-box'] && !values.mihomo) {
    console.error('Usage: node scripts/check-protocol-configs.mjs --sing-box /path/to/sing-box --mihomo /path/to/mihomo [--only case-name]');
    process.exit(1);
}

const uuid = 'd342d11e-d424-4583-b36e-524ab1f0afa4';
const base64 = value => Buffer.from(value).toString('base64url');
const publicKey = Buffer.alloc(32, 1).toString('base64url');
const echConfig = 'AEf+DQBDAAAgACD100XnGoMXaXeKl/eMqUgUdEV7Ix4ZaIvixhk2Xdb1CgAMAAEAAQABAAIAAQADAAxub2RlLmV4YW1wbGUAAA==';
const cases = [
    ['ss', 'shadowsocks', `ss://${base64('aes-128-gcm:p@ss:word')}@127.0.0.1:8388#SS`],
    ['ss-obfs', 'shadowsocks', `ss://${base64('aes-128-gcm:password')}@127.0.0.1:8388/?plugin=${encodeURIComponent('obfs-local;obfs=tls;obfs-host=node.example')}#SS-Obfs`],
    ['ss-v2ray-plugin', 'shadowsocks', `ss://${base64('aes-128-gcm:password')}@127.0.0.1:8388/?plugin=${encodeURIComponent('v2ray-plugin;mode=websocket;host=node.example;path=/ws;tls')}#SS-WS`],
    ['ssr', 'shadowsocksr', `ssr://${base64(`127.0.0.1:8388:auth_aes128_md5:aes-128-cfb:tls1.2_ticket_auth:${base64('password')}/?remarks=${base64('SSR')}&obfsparam=${base64('node.example')}`)}`],
    ['vmess-json', 'vmess', `vmess://${base64(JSON.stringify({ v: '2', ps: 'VMess-WS', add: '127.0.0.1', port: '443', id: uuid, aid: '0', scy: 'auto', net: 'ws', path: '/ws', host: 'node.example', tls: 'tls', sni: 'node.example' }))}`],
    ['vmess-uri', 'vmess', `vmess://${uuid}@127.0.0.1:443?security=tls&type=grpc&serviceName=example&alpn=h2&sni=node.example#VMess-gRPC`],
    ['vless', 'vless', `vless://${uuid}@127.0.0.1:443?security=tls&type=ws&path=%2Fws&host=node.example&sni=node.example#VLESS`],
    ['vless-grpc-multi', 'vless', `vless://${uuid}@127.0.0.1:443?security=reality&pbk=${publicKey}&sid=abcd&fp=chrome&sni=node.example&type=grpc&serviceName=example&mode=multi#VLESS-gRPC-multi`],
    ['vless-certificate-pin', 'vless', `vless://${uuid}@127.0.0.1:443?security=tls&sni=node.example&pcs=${'ab'.repeat(32)}#VLESS-pinned`],
    ['vless-reality', 'vless', `vless://${uuid}@127.0.0.1:443?security=reality&pbk=${publicKey}&sid=abcd&fp=chrome&sni=node.example&flow=xtls-rprx-vision#Reality`],
    ['vless-httpupgrade', 'vless', `vless://${uuid}@127.0.0.1:443?security=tls&type=httpupgrade&path=%2Fupgrade&host=node.example&sni=node.example#Upgrade`],
    ['trojan', 'trojan', 'trojan://p%40ss%3Aword@127.0.0.1:443?peer=node.example&alpn=h2%2Chttp%2F1.1#Trojan'],
    ['hysteria-v1', 'hysteria', 'hysteria://127.0.0.1:443?auth=password&upmbps=10&downmbps=50&peer=node.example#Hysteria1'],
    ['hysteria2', 'hysteria2', 'hysteria2://password@127.0.0.1:443?sni=node.example&obfs=salamander&obfs-password=obfs-password#Hysteria2'],
    ['hy2-hopping', 'hysteria2', 'hy2://password@127.0.0.1:20000-20002,443?sni=node.example#Hopping'],
    ['hy2-gecko', 'hysteria2', 'hy2://password@127.0.0.1:443?sni=node.example&obfs=gecko&obfs-password=obfs-password#Gecko'],
    ['tuic', 'tuic', `tuic://${uuid}:password@127.0.0.1:443?sni=node.example&alpn=h3&congestion_control=bbr#TUIC`],
    ['anytls', 'anytls', 'anytls://password@127.0.0.1?sni=node.example&insecure=0#AnyTLS'],
    ['ss-2022', 'shadowsocks', `ss://2022-blake3-aes-128-gcm:${encodeURIComponent(Buffer.alloc(16, 1).toString('base64'))}@127.0.0.1:8388#SS2022`],
    ['vmess-h2', 'vmess', `vmess://${uuid}@127.0.0.1:443?security=tls&type=http&host=node.example&path=%2Fh2&sni=node.example#VMess-H2`],
    ['vless-ws-early-data', 'vless', `vless://${uuid}@127.0.0.1:443?security=tls&type=ws&path=%2Fws%3Fed%3D2048&host=node.example&sni=node.example#EarlyData`],
    ['vless-xhttp', 'vless', `vless://${uuid}@127.0.0.1:443?security=tls&type=xhttp&path=%2Fxhttp&host=node.example&sni=node.example&mode=auto#XHTTP`],
    ['trojan-h2', 'trojan', 'trojan://password@127.0.0.1:443?type=h2&host=node.example&sni=node.example#Trojan-H2'],
    ['hysteria-v1-obfs', 'hysteria', 'hysteria://127.0.0.1:443?auth=password&upmbps=10&downmbps=50&peer=node.example&obfs=xplus&obfsParam=obfs-password#Hysteria1-Obfs'],
    ['hy2-ech', 'hysteria2', `hy2://password@127.0.0.1:443?sni=node.example&ech=${encodeURIComponent(echConfig)}#ECH`],
    ['hy2-gecko-options', 'hysteria2', 'hy2://password@127.0.0.1:443?sni=node.example&obfs=gecko&obfs-password=obfs-password&obfs-min-packet-size=512&obfs-max-packet-size=1200#GeckoOptions'],
    ['hy2-random-hopping', 'hysteria2', 'hy2://password@127.0.0.1:20000-20002,443?sni=node.example&hop-interval=15&hop-interval-max=30#RandomHopping']
];
const unsupported = {
    ssr: { 'sing-box': /ShadowsocksR.*removed/i },
    'vless-certificate-pin': { 'sing-box': /certificate fingerprint pinning/i },
    'vless-xhttp': { 'sing-box': /unsupported transport xhttp/i },
    'trojan-h2': { mihomo: /Trojan only supports/i }
};

const directory = mkdtempSync(join(tmpdir(), 'sublink-protocol-check-'));
let passed = 0;
let failed = 0;
try {
    for (const [label, expectedType, uri] of cases) {
        if (values.only && label !== values.only) continue;
        for (const client of ['sing-box', 'mihomo']) {
            if (!values[client]) continue;
            try {
                const proxy = await ProxyParser.parse(uri);
                assert.equal(proxy?.type, expectedType, 'protocol dispatch');
                assert.ok(proxy.tag, 'a selectable node needs a name');
                const builder = client === 'sing-box'
                    ? new SingboxConfigBuilder('', [], [], null, 'en', null, false, false, undefined, undefined, '1.14')
                    : new ClashConfigBuilder('', [], [], null, 'en', null);
                if (unsupported[label]?.[client]) {
                    assert.throws(() => builder.convertProxy(proxy), unsupported[label][client]);
                    console.log(`PASS ${client}/${label}: explicitly unsupported`);
                    passed++;
                    continue;
                }
                const converted = builder.convertProxy(proxy);
                const config = client === 'sing-box' ? { outbounds: [converted] } : { mode: 'direct', proxies: [converted] };
                const filename = join(directory, `${client}-${label}.json`);
                writeFileSync(filename, JSON.stringify(config));
                const args = client === 'sing-box' ? ['check', '-c', filename, '-D', directory] : ['-t', '-f', filename, '-d', directory];
                const result = spawnSync(resolve(values[client]), args, { encoding: 'utf8', timeout: 20000 });
                if (result.error) throw result.error;
                assert.equal(result.status, 0, `${result.stdout || ''}${result.stderr || ''}`);
                console.log(`PASS ${client}/${label}`);
                passed++;
            } catch (error) {
                console.error(`FAIL ${client}/${label}: ${error.message}`);
                failed++;
            }
        }
    }
} finally {
    rmSync(directory, { recursive: true, force: true });
}
console.log(`Native configuration checks: ${passed} passed, ${failed} failed`);
if (failed || !passed) process.exitCode = 1;
