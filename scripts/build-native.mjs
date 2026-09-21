import { copyFile, cp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { spawn, spawnSync } from 'node:child_process';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const packageJson = JSON.parse(await readFile(path.join(rootDir, 'package.json'), 'utf8'));
const platform = { win32: 'windows', darwin: 'macos' }[process.platform] || process.platform;
const arch = { x64: 'x64', arm64: 'arm64' }[process.arch] || process.arch;
const releaseName = `sublink-worker-v${packageJson.version}-${platform}-${arch}`;
const nativeDir = path.join(rootDir, 'dist', 'native');
const releaseDir = path.join(rootDir, 'dist', 'release');
const packageDir = path.join(releaseDir, releaseName);
const executableName = process.platform === 'win32' ? 'sublink-worker.exe' : 'sublink-worker';
const executablePath = path.join(packageDir, executableName);
const seaBlob = path.join(nativeDir, 'sea-prep.blob');
const seaConfig = path.join(nativeDir, 'sea-config.json');

await rm(nativeDir, { recursive: true, force: true });
await rm(releaseDir, { recursive: true, force: true });
await mkdir(nativeDir, { recursive: true });
await mkdir(packageDir, { recursive: true });

runNpm(['run', 'build:node']);
await writeFile(seaConfig, JSON.stringify({
    main: path.join(rootDir, 'dist', 'node-server.cjs'),
    output: seaBlob,
    disableExperimentalSEAWarning: true,
    useSnapshot: false,
    useCodeCache: false
}, null, 2));
run(process.execPath, ['--experimental-sea-config', seaConfig]);

await copyFile(process.execPath, executablePath);
removeSignature(executablePath);
injectSeaBlob(executablePath);
if (process.platform === 'darwin') {
    run('codesign', ['--sign', '-', executablePath]);
}

await cp(path.join(rootDir, 'public'), path.join(packageDir, 'public'), { recursive: true });
await copyFile(path.join(rootDir, 'README.md'), path.join(packageDir, 'README.md'));
await copyFile(path.join(rootDir, 'LICENSE'), path.join(packageDir, 'LICENSE'));

await smokeTest(executablePath, packageDir);
const archivePath = await createArchive(packageDir, releaseName);
console.log(`Created ${path.relative(rootDir, archivePath)}`);

function runNpm(args) {
    if (process.env.npm_execpath) {
        run(process.execPath, [process.env.npm_execpath, ...args]);
        return;
    }
    run(process.platform === 'win32' ? 'npm.cmd' : 'npm', args, {
        shell: process.platform === 'win32'
    });
}

function run(command, args, options = {}) {
    const result = spawnSync(command, args, {
        cwd: rootDir,
        encoding: 'utf8',
        stdio: 'inherit',
        ...options
    });
    if (result.error) throw result.error;
    if (result.status !== 0) {
        throw new Error(`${command} exited with status ${result.status}`);
    }
}

function capture(command, args) {
    const result = spawnSync(command, args, {
        cwd: rootDir,
        encoding: 'utf8',
        windowsHide: true
    });
    if (result.error || result.status !== 0) return '';
    return result.stdout.trim();
}

function removeSignature(target) {
    if (process.platform === 'darwin') {
        run('codesign', ['--remove-signature', target]);
        return;
    }
    if (process.platform !== 'win32') return;

    const signtool = process.env.SIGNTOOL_PATH ||
        capture('where.exe', ['signtool.exe']).split(/\r?\n/)[0] ||
        capture('powershell.exe', [
            '-NoProfile',
            '-Command',
            '(Get-ChildItem "${env:ProgramFiles(x86)}\\Windows Kits\\10\\bin\\*\\x64\\signtool.exe" -ErrorAction SilentlyContinue | Sort-Object FullName | Select-Object -Last 1).FullName'
        ]);
    if (!signtool) throw new Error('signtool.exe is required to build the Windows SEA executable');
    run(signtool, ['remove', '/s', target]);
}

function injectSeaBlob(target) {
    const args = [
        'exec', '--', 'postject', target, 'NODE_SEA_BLOB', seaBlob,
        '--sentinel-fuse', 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2'
    ];
    if (process.platform === 'darwin') {
        args.push('--macho-segment-name', 'NODE_SEA');
    }
    runNpm(args);
}

async function smokeTest(target, cwd) {
    const port = 18000 + Math.floor(Math.random() * 1000);
    const child = spawn(target, [], {
        cwd,
        env: { ...process.env, PORT: String(port), STATIC_DIR: path.join(cwd, 'public') },
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe']
    });
    let output = '';
    child.stdout.on('data', chunk => { output += chunk; });
    child.stderr.on('data', chunk => { output += chunk; });

    try {
        const deadline = Date.now() + 20000;
        while (Date.now() < deadline) {
            if (child.exitCode !== null) {
                throw new Error(`Native server exited before the smoke test completed:\n${output}`);
            }
            try {
                const response = await fetch(`http://127.0.0.1:${port}/`);
                const body = await response.text();
                if (response.ok && body.includes('Sublink Worker')) {
                    console.log(`Native smoke test passed on ${platform}-${arch}`);
                    return;
                }
            } catch (_) {
                // The process may still be binding its listening socket.
            }
            await new Promise(resolve => setTimeout(resolve, 250));
        }
        throw new Error(`Native server did not become ready:\n${output}`);
    } finally {
        if (child.exitCode === null) {
            await new Promise(resolve => {
                const finish = () => {
                    clearTimeout(timeout);
                    child.off('exit', finish);
                    resolve();
                };
                const timeout = setTimeout(finish, 3000);
                child.once('exit', finish);
                child.kill();
            });
        }
    }
}

async function createArchive(sourceDir, name) {
    if (process.platform === 'win32') {
        const archive = path.join(releaseDir, `${name}.zip`);
        run('tar.exe', ['-a', '-c', '-f', archive, '-C', sourceDir, '.']);
        return archive;
    }
    const archive = path.join(releaseDir, `${name}.tar.gz`);
    run('tar', ['-czf', archive, '-C', sourceDir, '.']);
    return archive;
}
