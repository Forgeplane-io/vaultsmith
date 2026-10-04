// Run with `node scripts/ci-paths-test.cjs` after installing frontend dependencies.
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { createRequire } = require('node:module');
const { join } = require('node:path');

const frontendRequire = createRequire(join(__dirname, '../frontend/package.json'));
const picomatch = frontendRequire('picomatch');
const { parse } = frontendRequire('yaml');
const filters = parse(readFileSync(join(__dirname, '../.github/ci-paths.yml'), 'utf8'));

for (const [path, expected] of [
  ['integration/Caddyfile', ['native_integration']],
  ['integration/docker-compose.yml', ['native_integration']],
  ['scripts/integration-native.sh', ['native_integration']],
  ['integration/unrelated.txt', []],
  ['integration/Caddyfile-idp', ['native_integration']],
]) {
  // paths-filter defaults to any matching pattern, with dotfiles included.
  const selected = Object.entries(filters)
    .filter(([, patterns]) => picomatch(patterns, { dot: true })(path))
    .map(([name]) => name);
  console.log(`${path}: ${JSON.stringify(selected)}`);
  assert.deepEqual(selected, expected, path);
}
