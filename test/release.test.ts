import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { promisify } from 'node:util';
import test from 'node:test';

const execFileAsync = promisify(execFile);
const root = new URL('../', import.meta.url);
const releaseScript = new URL('scripts/prepare-release.mjs', root);

test('resolves stable release versions without a v prefix', async () => {
  assert.equal(await resolveVersion(), '0.1.0');
  assert.equal(await resolveVersion('--latest', '1.2.3', '--increment', 'patch'), '1.2.4');
  assert.equal(await resolveVersion('--latest', '1.2.3', '--increment', 'minor'), '1.3.0');
  assert.equal(await resolveVersion('--latest', '1.2.3', '--increment', 'major'), '2.0.0');
  assert.equal(await resolveVersion('--latest', '1.2.3', '--version', '1.4.0'), '1.4.0');
  await assert.rejects(resolveVersion('--latest', '1.2.3', '--version', '1.2.3'), /must be newer/);
  await assert.rejects(resolveVersion('--version', 'v1.2.3'), /without a v prefix/);
});

test('release workflow requires deployed main, the GitHub token, and pre-merged version metadata', async () => {
  const workflow = await readFile(new URL('.github/workflows/release.yml', root), 'utf8');
  assert.match(workflow, /workflow_dispatch:/);
  assert.match(workflow, /contents: write/);
  assert.match(workflow, /deployments: read/);
  assert.match(workflow, /secrets\.KEYGADGETS_GH_TOKEN/g);
  assert.match(workflow, /environment=github-pages/);
  assert.match(workflow, /prepare-release\.mjs resolve/);
  assert.match(workflow, /prepare-release\.mjs apply/);
  assert.match(workflow, /Require pre-merged version metadata/);
  assert.match(workflow, /gh release create/);
  assert.match(workflow, /--verify-tag/);
});

test('npm workflow publishes only stable GitHub Releases with bootstrap or OIDC', async () => {
  const workflow = await readFile(new URL('.github/workflows/npm-publish.yml', root), 'utf8');
  assert.match(workflow, /workflow_dispatch:/);
  assert.match(workflow, /id-token: write/);
  assert.match(workflow, /name: npm/);
  assert.match(workflow, /npm@11\.19\.0/);
  assert.match(workflow, /Only a published stable GitHub Release/);
  assert.match(workflow, /@pkistudio\/keygadgets/);
  assert.match(workflow, /secrets\.KEYGADGETS_GH_TOKEN/g);
  assert.match(workflow, /inputs\.authentication == 'trusted'/);
  assert.match(workflow, /inputs\.authentication == 'token-bootstrap'/);
  assert.match(workflow, /secrets\.NPM_TOKEN/);
  assert.match(workflow, /npm publish --access public/g);
});

test('Pages workflow deploys and verifies the built site with official Pages credentials', async () => {
  const workflow = await readFile(new URL('.github/workflows/pages.yml', root), 'utf8');
  assert.match(workflow, /pages: write/);
  assert.match(workflow, /id-token: write/);
  assert.match(workflow, /actions\/deploy-pages@v5/);
  assert.match(workflow, /keygadgets-pages-source/);
  assert.match(workflow, /cmp --silent/);
  assert.doesNotMatch(workflow, /KEYGADGETS_GH_TOKEN/);
});

test('version preparation synchronizes all package version markers', async () => {
  const script = await readFile(releaseScript, 'utf8');
  assert.match(script, /packageJson\.version = normalized/);
  assert.match(script, /packageLock\.version = normalized/);
  assert.match(script, /packageLock\.packages\[''\]\.version = normalized/);
  assert.match(script, /src\/version\.ts/);
  assert.match(script, /README\.md/);

  const packageJson = JSON.parse(await readFile(new URL('package.json', root), 'utf8')) as {
    version: string;
    publishConfig: { access: string; registry: string };
  };
  const packageLock = JSON.parse(await readFile(new URL('package-lock.json', root), 'utf8')) as {
    version: string;
    packages: Record<string, { version?: string }>;
  };
  const versionSource = await readFile(new URL('src/version.ts', root), 'utf8');
  const readme = await readFile(new URL('README.md', root), 'utf8');
  assert.equal(packageLock.version, packageJson.version);
  assert.equal(packageLock.packages['']?.version, packageJson.version);
  assert.deepEqual(packageJson.publishConfig, {
    access: 'public',
    registry: 'https://registry.npmjs.org/'
  });
  assert.match(versionSource, new RegExp(`: '${escapeRegExp(packageJson.version)}';`));
  assert.match(readme, new RegExp(`^Current version: ${escapeRegExp(packageJson.version)}$`, 'm'));
});

async function resolveVersion(...args: string[]): Promise<string> {
  const { stdout } = await execFileAsync(process.execPath, [releaseScript.pathname, 'resolve', ...args], {
    cwd: new URL('.', root)
  });
  return stdout;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
