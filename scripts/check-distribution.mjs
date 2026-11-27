import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';

const root = fs.realpathSync.native(process.cwd());
const gitEnv = { ...process.env };
const openApiPath = 'docs/openapi-default.json';
const blockedReleaseTag = 'v1.0.0';
const privateNames = new Set([
    'email.txt', 'gmlogin.txt', 'results.json', 'summary.json', 'profiles.json',
    'profile.json', 'storage-state.json', 'traffic.ndjson', 'attribution-index.json',
    'camoufox-audit-report.json', 'sslkeylog.txt', '_shared_sslkeylog.txt', 'pre-tls-wire.log'
]);

function git(args, { showOutput = false, allowMissing = false } = {}) {
    const result = spawnSync('git', args, {
        cwd: root,
        env: gitEnv,
        encoding: 'utf8',
        maxBuffer: 16 * 1024 * 1024,
        stdio: showOutput ? 'inherit' : 'pipe'
    });
    if (allowMissing && result.status === 1) return '';
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
        roots.add(canonicalPath(absolute));
    }
    const relativeRoots = [...roots].map((directory) => path.relative(root, directory));
    if (relativeRoots.includes('')) {
        throw new Error('Move application state and Camoufox profiles out of the repository root before distributing files.');
    }
    return relativeRoots
        .filter((directory) => directory !== '..' && !directory.startsWith(`..${path.sep}`) && !path.isAbsolute(directory))
        .map((directory) => directory.split(path.sep).join('/'));
}

function canonicalPath(absolute) {
    try {
        // The native implementation returns the actual spelling on case-insensitive volumes.
        return fs.realpathSync.native(absolute);
    } catch (error) {
        if (error.code !== 'ENOENT' && error.code !== 'ENOTDIR') throw error;
        const parent = path.dirname(absolute);
        if (parent === absolute) return absolute;
        return path.join(canonicalPath(parent), path.basename(absolute));
    }
}

function insideStorage(file, stores) {
    if (stores.length === 0) return false;
    const belongsTo = (candidate) => stores.some((directory) =>
        candidate === directory || candidate.startsWith(`${directory}/`));
    if (belongsTo(file)) return true;
    const actual = path.relative(root, canonicalPath(path.resolve(root, file))).split(path.sep).join('/');
    return belongsTo(actual);
}

function isPrivatePath(file) {
    if (file === '.env.example') return false;

    const name = path.posix.basename(file).toLowerCase();
    return privateNames.has(name)
        || /(?:^|\/)(?:logs|data|profiles|\.gpm|gpm-data|\.native|(?:results|summary)\.json\.lock|traffic\/(?:payloads|\.private))\//i.test(file)
        || /(?:^|\/)config\/proxies\.txt$/i.test(file)
        || /\.(?:env|emv)(?:\.|$)|\.(?:har|log|tgz)$|\.moz_log/.test(name);
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

function checkOpenApiExamples(contents) {
    const message = `Use synthetic identifiers and credential placeholders in ${openApiPath}.`;
    let safe;
    try {
        const specification = JSON.parse(contents);
        const responseExample = (route) => specification.paths[route].post.responses['200'].content['application/json'].example;
        const requestExample = (route) => specification.paths[route].post.requestBody.content['application/json'].example;
        const profile = responseExample('/api/profile/detail');
        const browser = responseExample('/api/browser/openBrowser');
        const proxies = [
            profile.proxy,
            requestExample('/api/profile/advancedCreateProfile').proxy,
            requestExample('/api/profile/updateProfileBaseProxy'),
            requestExample('/api/proxy/proxyDetect'),
            requestExample('/api/proxy/createBaseProxy')
        ];
        const cookies = JSON.parse(profile.cookie);
        const token = specification.components.schemas.login_with_token.properties.token.example;
        const identifierPattern = /\b(?:[0-9a-f]{32}|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}|[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5})\b/gi;
        const fixedIds = JSON.stringify(specification).match(identifierPattern) ?? [];
        safe = fixedIds.every((identifier) => /^0+(?:[-:]0+)*$/.test(identifier)) &&
            profile.fingerprint.computerName === 'REPLACE_WITH_COMPUTER_NAME' &&
            profile.fingerprint.macAddr === '00:00:00:00:00:00' &&
            profile.fingerprint.modelName === 'REPLACE_WITH_MODEL_NAME' &&
            profile.sk === 'REPLACE_WITH_SECRET_KEY' && token === 'REPLACE_WITH_API_TOKEN' &&
            cookies.every((cookie) => cookie.domain === 'example.invalid' && cookie.value === 'REPLACE_WITH_COOKIE_VALUE') &&
            proxies.every((proxy) => proxy.host === '192.0.2.10' &&
                proxy.proxyUsername === 'REPLACE_WITH_PROXY_USERNAME' && proxy.proxyPassword === 'REPLACE_WITH_PROXY_PASSWORD') &&
            browser.ws === 'ws://example.invalid:9222/devtools/browser/00000000-0000-0000-0000-000000000000' &&
            browser.port === 9222 && browser.pid === 0 && browser.seq === 0;
    } catch {
        throw new Error(message);
    }
    if (!safe) throw new Error(message);
}

function checkFileContents(file, readContents, sensitiveFileError) {
    const registryConfig = path.posix.basename(file).toLowerCase() === '.npmrc';
    if (file !== openApiPath && !registryConfig) return;
    const contents = readContents();
    if (contents === undefined) return;
    if (file === openApiPath) checkOpenApiExamples(contents);
    else if (hasRegistryCredentials(contents)) throw sensitiveFileError(file);
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
        checkFileContents(file, () => {
            if (staged) return git(['cat-file', 'blob', `:${file}`]);
            const stat = fs.lstatSync(file, { throwIfNoEntry: false });
            if (stat && !stat.isFile()) throw sensitiveCommitFile(file);
            return stat ? fs.readFileSync(file, 'utf8') : undefined;
        }, sensitiveCommitFile);
    }
}

function checkSourceTree(stores, ref) {
    const commit = git(['rev-parse', '--verify', '--end-of-options', `${ref}^{commit}`]).trim();
    const files = git(['ls-tree', '-rz', '--name-only', '--full-tree', commit]).split('\0').filter(Boolean);
    const sensitiveSourceFile = (file) => new Error(`Sensitive file in the source archive: ${JSON.stringify(file)}`);
    // Git archives are built from the selected commit tree. Check the tree's exact
    // paths and blobs even when the worktree or index has newer changes.
    for (const file of files) {
        if (isPrivatePath(file) || insideStorage(file, stores)) throw sensitiveSourceFile(file);
        checkFileContents(file, () => git(['cat-file', 'blob', `${commit}:${file}`]), sensitiveSourceFile);
    }
}

function checkInitialPushHistory() {
    if (git(['rev-parse', '--is-shallow-repository']).trim() === 'true') {
        throw new Error('Inspect the full branch history before its first push to a new remote.');
    }
    const head = git(['rev-parse', '--verify', '--quiet', 'HEAD'], { allowMissing: true }).trim();
    if (!head) return;
    const commits = git([
        'log', '--full-history', '--no-renames', '--diff-filter=AMT', '--format=%H', head, '--', openApiPath
    ]).trim().split('\n').filter(Boolean);
    for (const commit of commits) {
        const contents = git(['cat-file', 'blob', `${commit}:${openApiPath}`]);
        try {
            checkOpenApiExamples(contents);
        } catch {
            throw new Error('The branch retains earlier OpenAPI examples. See GITHUB_SETUP.md before its first push to a new remote.');
        }
    }
}

function packageManifest() {
    return JSON.parse(fs.readFileSync('package.json', 'utf8'));
}

function allowedFiles({ files }) {
    const result = new Set(['package.json']);
    for (const entry of files) {
        const file = typeof entry === 'string' ? entry.replace(/^\//, '') : '';
        if (!/^[\w.-]+(?:\/[\w.-]+)*$/.test(file) || !entry.includes('/') ||
            file.split('/').some((part) => part === '.' || part === '..') || result.has(file)) {
            throw new Error(`Expected an exact package path: ${JSON.stringify(entry)}`);
        }
        result.add(file);
    }
    return result;
}

function checkPackage(stores) {
    const publicFiles = allowedFiles(packageManifest());
    // npm can include top-level README, license and copying files automatically.
    for (const file of fs.readdirSync(root)) {
        if (/^(?:readme|licen[cs]e|copying)(?:\..*[^~$])?$/i.test(file) && !publicFiles.has(file)) {
            throw new Error(`Review the additional file that npm would include: ${JSON.stringify(file)}`);
        }
    }
    for (const file of publicFiles) {
        const stat = fs.lstatSync(file, { throwIfNoEntry: false });
        if (isPrivatePath(file) || insideStorage(file, stores) ||
            !stat?.isFile() || fs.realpathSync.native(file) !== path.join(root, file)) {
            throw new Error(`Expected an allowed public file for packaging: ${JSON.stringify(file)}`);
        }
        if (file === openApiPath) checkOpenApiExamples(fs.readFileSync(file, 'utf8'));
    }
}

function checkPackReport() {
    // npm pack --json lists entries read from the generated tar, including implicit files.
    const reports = JSON.parse(fs.readFileSync(0, 'utf8'));
    const report = Array.isArray(reports) && reports.length === 1 ? reports[0] : null;
    const manifest = packageManifest();
    const filename = `${manifest.name.replace(/^@/, '').replace('/', '-')}-${manifest.version}.tgz`;
    if (report?.name !== manifest.name || report.version !== manifest.version ||
        report.filename !== filename || !/^[a-z\d_.+-]+\.tgz$/i.test(filename) || !Array.isArray(report.files)) {
        throw new Error('Expected one npm archive for the current package and version.');
    }
    const remaining = allowedFiles(manifest);
    for (const entry of report.files) {
        if (!remaining.delete(entry?.path)) {
            throw new Error(`Unexpected npm archive member: ${JSON.stringify(entry?.path)}`);
        }
    }
    if (remaining.size !== 0) {
        throw new Error(`Missing npm archive member: ${JSON.stringify(remaining.values().next().value)}`);
    }
    const stat = fs.lstatSync(filename, { throwIfNoEntry: false });
    if (!stat?.isFile()) throw new Error('Expected the generated npm archive in the package root.');
    const digest = createHash('sha512').update(fs.readFileSync(filename)).digest('base64');
    if (report.integrity !== `sha512-${digest}`) throw new Error('npm archive does not match its pack report.');
    console.log(filename);
}

try {
    switch (process.argv[2]) {
        case 'stage': {
            const stores = await storagePaths();
            checkGitFiles(stores, true);
            checkGitFiles(stores, false);
            git(['add', '--', '.', ...stores.map((directory) => `:(top,literal,exclude)${directory}`)], { showOutput: true });
            checkGitFiles(stores, true);
            break;
        }
        case 'index':
            checkGitFiles(await storagePaths(), true);
            break;
        case 'source':
            checkSourceTree(await storagePaths(), process.argv[3] ?? 'HEAD');
            break;
        case 'history':
            checkInitialPushHistory();
            break;
        case 'pack':
            checkPackage(await storagePaths());
            break;
        case 'archive':
            checkPackReport();
            break;
        case 'tag': {
            if (process.argv[3] === blockedReleaseTag) {
                throw new Error(`${blockedReleaseTag} retains historical OpenAPI example data. Choose a new version and tag. See GITHUB_SETUP.md.`);
            }
            const expectedTag = `v${packageManifest().version}`;
            if (process.argv[3] !== expectedTag) throw new Error(`Release tag must be ${expectedTag}.`);
            break;
        }
        default:
            throw new Error('Use stage, index, source, history, pack, archive or tag to check files before distribution.');
    }
} catch (error) {
    console.error(error.message);
    process.exitCode = 1;
}
