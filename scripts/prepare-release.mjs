import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const INITIAL_VERSION = '0.1.0';
const SEMVER_PATTERN = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const rootDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');

export function parseVersion(value, label = 'version') {
  const normalized = String(value || '').trim();
  const match = normalized.match(SEMVER_PATTERN);
  if (!match) throw new Error(`${label} must use X.Y.Z without a v prefix: ${normalized || '(empty)'}`);
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
    value: normalized
  };
}

function compareVersions(left, right) {
  for (const key of ['major', 'minor', 'patch']) {
    if (left[key] !== right[key]) return left[key] - right[key];
  }
  return 0;
}

export function incrementVersion(version, increment) {
  const parsed = parseVersion(version, 'latest release version');
  switch (increment) {
    case 'major': return `${parsed.major + 1}.0.0`;
    case 'minor': return `${parsed.major}.${parsed.minor + 1}.0`;
    case 'patch': return `${parsed.major}.${parsed.minor}.${parsed.patch + 1}`;
    default: throw new Error(`increment must be major, minor, or patch: ${increment}`);
  }
}

export function resolveVersion({ latest = '', requested = '', increment = 'patch' } = {}) {
  const latestValue = String(latest || '').trim();
  const requestedValue = String(requested || '').trim();
  if (requestedValue) {
    const requestedVersion = parseVersion(requestedValue, 'requested version');
    if (latestValue && compareVersions(requestedVersion, parseVersion(latestValue, 'latest release version')) <= 0) {
      throw new Error(`requested version ${requestedValue} must be newer than latest release ${latestValue}`);
    }
    return requestedValue;
  }
  return latestValue ? incrementVersion(latestValue, increment) : INITIAL_VERSION;
}

function replaceExactlyOnce(relativePath, pattern, replacement) {
  const filePath = path.join(rootDir, relativePath);
  const source = readFileSync(filePath, 'utf8');
  const matches = source.match(pattern);
  if (!matches || matches.length !== 1) {
    throw new Error(`expected one version marker in ${relativePath}, found ${matches ? matches.length : 0}`);
  }
  writeFileSync(filePath, source.replace(pattern, replacement));
}

export function applyVersion(version) {
  const normalized = parseVersion(version).value;
  const packagePath = path.join(rootDir, 'package.json');
  const lockPath = path.join(rootDir, 'package-lock.json');
  const packageJson = JSON.parse(readFileSync(packagePath, 'utf8'));
  const packageLock = JSON.parse(readFileSync(lockPath, 'utf8'));
  packageJson.version = normalized;
  packageLock.version = normalized;
  packageLock.packages[''].version = normalized;
  writeFileSync(packagePath, `${JSON.stringify(packageJson, null, 2)}\n`);
  writeFileSync(lockPath, `${JSON.stringify(packageLock, null, 2)}\n`);
  replaceExactlyOnce(
    'src/version.ts',
    /: '\d+\.\d+\.\d+';/g,
    `: '${normalized}';`
  );
  replaceExactlyOnce('README.md', /^Current version: \S+$/gm, `Current version: ${normalized}`);
}

function readOption(args, option, fallback = '') {
  const index = args.indexOf(option);
  return index === -1 ? fallback : (args[index + 1] || '');
}

function main(args) {
  const command = args[0];
  if (command === 'resolve') {
    process.stdout.write(resolveVersion({
      latest: readOption(args, '--latest'),
      requested: readOption(args, '--version'),
      increment: readOption(args, '--increment', 'patch')
    }));
    return;
  }
  if (command === 'apply') {
    applyVersion(args[1]);
    return;
  }
  throw new Error('usage: prepare-release.mjs resolve [--latest X.Y.Z] [--version X.Y.Z] [--increment major|minor|patch] | apply X.Y.Z');
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
