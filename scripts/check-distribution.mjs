import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const root = fs.realpathSync(process.cwd());
const gitEnv = { ...process.env };
const privateNames = new Set([
    'email.txt', 'gmlogin.txt', 'results.json', 'summary.json', 'profiles.json',
    'profile.json', 'storage-state.json', 'traffic.ndjson', 'attribution-index.json',
    'camoufox-audit-report.json', 'sslkeylog.txt', '_shared_sslkeylog.txt', 'pre-tls-wire.log'
]);

function git(args, showOutput = false) {
    const result = spawnSync('git', args, {
        cwd: root,
        env: gitEnv,
        encoding: 'utf8',
        maxBuffer: 16 * 1024 * 1024,
        stdio: showOutput ? 'inherit' : 'pipe'
    });
    if (result.status !== 0) throw new Error(`Git ${args[0]} failed.`);
    return result.stdout;
}

async function storagePaths() {
    // The runtime configuration owns .env and .emv precedence. Keep its diagnostics
    // out of the distribution check and use the original environment for Git.
    const warn = console.warn;
    console.warn = () => {};
    let storageDir;
    try {
        const { config } = await import('../src/config.js');
        storageDir = config.camoufox.storageDir;
    } finally {
        console.warn = warn;
    }

    const { STATE_DIRECTORY } = await import('../src/utils/state-paths.js');
    const roots = new Set();
    const configuredPaths = [STATE_DIRECTORY, storageDir, process.env.CAMOUFOX_PROFILES_DIR];
    for (const configured of configuredPaths.filter(Boolean)) {
        const absolute = path.resolve(configured);
        roots.add(absolute);
        try {
            roots.add(fs.realpathSync(absolute));
        } catch (error) {
            if (error.code !== 'ENOENT') throw error;
        }
    }
    const relativeRoots = [...roots].map((directory) => path.relative(root, directory));
    if (relativeRoots.includes('')) {
        throw new Error('Move application state and Camoufox profiles out of the repository root before distributing files.');
    }
    return relativeRoots
        .filter((directory) => directory !== '..' && !directory.startsWith(`..${path.sep}`) && !path.isAbsolute(directory))
        .map((directory) => directory.split(path.sep).join('/'));
}

function insideStorage(file, stores) {
    return stores.some((directory) => file === directory || file.startsWith(`${directory}/`));
}

function isPrivatePath(file) {
    if (file === '.env.example') return false;

    const name = path.posix.basename(file).toLowerCase();
    return privateNames.has(name)
        || /(?:^|\/)(?:logs|data|profiles|\.gpm|gpm-data|\.native|(?:results|summary)\.json\.lock|traffic\/(?:payloads|\.private))\//i.test(file)
        || /(?:^|\/)config\/proxies\.txt$/i.test(file)
        || /\.(?:env|emv)(?:\.|$)|\.har$|\.moz_log/.test(name);
}

function hasRegistryCredentials(contents) {
    for (const line of contents.split(/[\r\n]+/)) {
        const match = /^([^#;][^=]*?)\s*=\s*(.*)$/.exec(line.trim());
        if (!match) continue;

        let key = match[1];
        if (/^".*"$/.test(key)) {
            try {
                key = JSON.parse(key);
            } catch {
                return true;
            }
        }
        key = key.replace(/^'(.*)'$/, '$1').trim();
        const value = match[2].trim();
        if (!value || /^(?:\$\{[A-Z_]\w*\??\}|(['"])\$\{[A-Z_]\w*\??\}\1)(?:\s+[;#].*)?$/i.test(value)) continue;
        const setting = key.slice(key.lastIndexOf(':') + 1);
        if (setting.includes('${') || /^(?:_authToken|_auth|_password|username|cert|key)(?:\[\])?$/i.test(setting)) return true;
        if (/^(?:[^:]+:)?(?:registry|proxy|https-proxy)$/i.test(key) && /:\/\/[^/\s]*@/.test(value)) return true;
    }
    return false;
}

function sensitiveCommitFile(file) {
    return new Error(`Sensitive file would be included in the commit: ${JSON.stringify(file)}`);
}

function checkGitFiles(stores, staged) {
    const args = ['ls-files', '-z', '--cached'];
    if (!staged) args.push('--others', '--exclude-standard');
    for (const file of git(args).split('\0').filter(Boolean)) {
        if (insideStorage(file, stores)) {
            if (staged) throw sensitiveCommitFile(file);
            continue;
        }
        if (isPrivatePath(file)) throw sensitiveCommitFile(file);
        if (path.posix.basename(file).toLowerCase() !== '.npmrc') continue;

        const stat = staged ? null : fs.lstatSync(file, { throwIfNoEntry: false });
        if (stat && !stat.isFile()) throw sensitiveCommitFile(file);
        const contents = staged ? git(['cat-file', 'blob', `:${file}`]) : stat && fs.readFileSync(file, 'utf8');
        if (contents && hasRegistryCredentials(contents)) throw sensitiveCommitFile(file);
    }
}

function checkPackage(stores) {
    const { files } = JSON.parse(fs.readFileSync('package.json', 'utf8'));
    const publicFiles = new Set(['package.json', ...files]);
    // npm can include top-level README, license and copying files automatically.
    for (const file of fs.readdirSync(root)) {
        if (/^(?:readme|licen[cs]e|copying)(?:\..*[^~$])?$/i.test(file) && !publicFiles.has(file)) {
            throw new Error(`Review the additional file that npm would include: ${JSON.stringify(file)}`);
        }
    }
    for (const file of publicFiles) {
        const stat = fs.lstatSync(file, { throwIfNoEntry: false });
        if (!/^[\w.-]+(?:\/[\w.-]+)*$/.test(file) || isPrivatePath(file) || insideStorage(file, stores)
            || !stat?.isFile() || fs.realpathSync(file) !== path.join(root, file)) {
            throw new Error(`Expected an allowed public file for packaging: ${JSON.stringify(file)}`);
        }
    }
}

try {
    const stores = await storagePaths();
    switch (process.argv[2]) {
        case 'stage':
            checkGitFiles(stores, true);
            checkGitFiles(stores, false);
            git(['add', '--', '.', ...stores.map((directory) => `:(top,literal,exclude)${directory}`)], true);
            checkGitFiles(stores, true);
            break;
        case 'index':
            checkGitFiles(stores, true);
            break;
        case 'pack':
            checkPackage(stores);
            break;
        default:
            throw new Error('Use stage, index or pack to check files before distribution.');
    }
} catch (error) {
    console.error(error.message);
    process.exitCode = 1;
}
