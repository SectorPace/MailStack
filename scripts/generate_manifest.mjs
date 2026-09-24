import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

const modulePath = new URL(import.meta.url).pathname;
const rootDir = path.resolve(path.dirname(modulePath.replace(/^\/(\w:)/, '$1')), '..');
const distDir = path.join(rootDir, 'dist');
const manifestPath = path.join(distDir, 'build-manifest.json');
const pkg = JSON.parse(fs.readFileSync(path.join(rootDir, 'package.json'), 'utf8'));
const version = fs.readFileSync(path.join(rootDir, 'VERSION'), 'utf8').trim();
// 与 scripts/package.py 的默认值保持同一个常量：归档的 mtime 由 package.py
// 固定，而 manifest 的 builtAt 是在「构建」这一步烙进去的。若这里退回墙上时间，
// 同源码重建一次就会得到不同的 build-manifest.json —— 归档哈希随之变化，
// RELEASE_CHECKLIST 的「第二次打包哈希一致」也就不再成立（release.yml 之所以
// 没暴露这个问题，只是因为它的 SOURCE_DATE_EPOCH 是 job 级 env）。
const sourceDateEpoch = process.env.SOURCE_DATE_EPOCH ?? '1704067200';

if (!fs.existsSync(distDir)) throw new Error('dist directory does not exist');
if (pkg.version !== version) throw new Error(`package.json version ${pkg.version} does not match VERSION ${version}`);

const sha256 = (content) => crypto.createHash('sha256').update(content).digest('hex');

function walkFiles(directory, relative = '') {
  return fs.readdirSync(directory, { withFileTypes: true })
    .sort((a, b) => a.name.localeCompare(b.name, 'en'))
    .flatMap((entry) => {
      const full = path.join(directory, entry.name);
      const rel = path.posix.join(relative, entry.name);
      if (full === manifestPath) return [];
      return entry.isDirectory() ? walkFiles(full, rel) : [rel];
    });
}

const criticalFiles = [
  'VERSION',
  'package.json',
  'package-lock.json',
  'backend/server.production.ts',
  'backend/mailstackctl.py',
  'webmail/server.mjs',
  'deploy/install.sh',
  'deploy/install-v05.sh',
  'deploy/install-mail-stack.sh',
  'deploy/mailstack-privileged',
  'mailstack.sh',
  'scripts/package.py',
  'scripts/generate_manifest.mjs'
];
const sourceHasher = crypto.createHash('sha256');
for (const rel of criticalFiles) {
  const full = path.join(rootDir, rel);
  if (!fs.statSync(full).isFile()) throw new Error(`critical source file is missing: ${rel}`);
  sourceHasher.update(`${rel}\0`);
  sourceHasher.update(fs.readFileSync(full));
  sourceHasher.update('\0');
}

const artifacts = Object.fromEntries(walkFiles(distDir).map((rel) => [rel, sha256(fs.readFileSync(path.join(distDir, rel)))]));
for (const required of ['index.html', 'server.cjs', 'webmail.cjs', 'webmail-public/index.html']) {
  if (!artifacts[required]) throw new Error(`required artifact is missing: ${required}`);
}

const manifest = {
  schemaVersion: 1,
  name: pkg.name,
  version,
  builtAt: new Date(Number(sourceDateEpoch) * 1000).toISOString(),
  nodeEngine: pkg.engines.node,
  buildTarget: 'standalone-inlined',
  sourceTreeHash: sourceHasher.digest('hex'),
  provenance: {
    bundler: 'esbuild',
    target: 'node20-cjs',
    environment: `${process.platform}-${process.arch}`,
    node: process.version
  },
  artifactsCount: Object.keys(artifacts).length,
  artifacts
};

fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
console.log(`Generated ${path.relative(rootDir, manifestPath)} with ${manifest.artifactsCount} artifacts`);
