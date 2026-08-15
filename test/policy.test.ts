import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import test from 'node:test';

const root = new URL('../', import.meta.url);

test('allows only the exact published PkiStudio integration packages', async () => {
  const packageJson = JSON.parse(await readFile(new URL('package.json', root), 'utf8')) as {
    dependencies: Record<string, string>;
  };
  const dependencies = Object.entries(packageJson.dependencies).filter(([name]) => name.startsWith('@pkistudio/'));
  assert.deepEqual(dependencies, [
    ['@pkistudio/dereditor', '0.1.4'],
    ['@pkistudio/x509gadgets', '0.2.1']
  ]);
});

test('uses no forbidden PkiStudio imports or repository coupling', async () => {
  const files = await sourceFiles(new URL('src/', root));
  const source = (await Promise.all(files.map((file) => readFile(file, 'utf8')))).join('\n');
  assert.doesNotMatch(source, /@pkistudio\/(?:pvkgadgets|certgadgets|pkistudiojs)/);
  assert.doesNotMatch(source, /github\.com\/pkistudio|raw\.githubusercontent\.com\/pkistudio/);
  assert.doesNotMatch(source, /from ['"]@pkistudio\/dereditor\/(?:app|static|docs|manuals)/);
  const x509Imports = [...source.matchAll(/['"](@pkistudio\/x509gadgets(?:\/[^'"]*)?)['"]/g)]
    .map((match) => match[1])
    .filter((value): value is string => Boolean(value));
  assert.deepEqual([...new Set(x509Imports)].sort(), [
    '@pkistudio/x509gadgets/app',
    '@pkistudio/x509gadgets/styles.css'
  ]);
});

test('uses no remote transport and supplies the packaged OID resolver', async () => {
  const app = await readFile(new URL('src/app.ts', root), 'utf8');
  const adapter = await readFile(new URL('src/dereditor-adapter.ts', root), 'utf8');
  const html = await readFile(new URL('index.html', root), 'utf8');
  const x509Html = await readFile(new URL('x509-viewer.html', root), 'utf8');
  assert.doesNotMatch(app, /\bfetch\s*\(|XMLHttpRequest|WebSocket|EventSource|sendBeacon/);
  assert.match(adapter, /oidResolver:\s*DerEditorOidResolver/);
  assert.match(adapter, /editable:\s*false/);
  assert.match(html, /connect-src 'none'/);
  assert.match(x509Html, /connect-src 'none'/);
});

test('lockfile contains only the approved PkiStudio packages', async () => {
  const lockfile = JSON.parse(await readFile(new URL('package-lock.json', root), 'utf8')) as {
    packages: Record<string, unknown>;
  };
  const installed = Object.keys(lockfile.packages).filter((path) => path.startsWith('node_modules/@pkistudio/'));
  assert.deepEqual(installed, [
    'node_modules/@pkistudio/dereditor',
    'node_modules/@pkistudio/x509gadgets'
  ]);
});

test('CI never checks out another PkiStudio repository', async () => {
  const workflow = await readFile(new URL('.github/workflows/ci.yml', root), 'utf8');
  assert.match(workflow, /npm run test:e2e/);
  assert.doesNotMatch(workflow, /pkistudio\/(?:pvkgadgets|certgadgets|pkistudiojs|dereditor|x509gadgets)/i);
});

async function sourceFiles(directory: URL): Promise<URL[]> {
  const files: URL[] = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = new URL(`${entry.name}${entry.isDirectory() ? '/' : ''}`, directory);
    if (entry.isDirectory()) files.push(...await sourceFiles(path));
    else if (entry.isFile() && entry.name.endsWith('.ts')) files.push(path);
  }
  return files;
}
