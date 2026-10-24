// Run with `node scripts/dependabot-auto-merge-test.cjs` after installing frontend dependencies.
// Failure cases: untrusted/fork/draft PRs, extra commits, missing metadata, mixed
// major/tooling updates, excessive token permissions, CI failures, stale heads,
// persistent merge intent after a head change, and merge errors.
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } = require('node:fs');
const { createRequire } = require('node:module');
const { join } = require('node:path');

const root = join(__dirname, '..');
const frontendRequire = createRequire(join(root, 'frontend/package.json'));
const { parse } = frontendRequire('yaml');
const workflowText = readFileSync(join(root, '.github/workflows/dependabot-auto-merge.yml'), 'utf8');
const workflow = parse(workflowText);
const job = workflow.jobs.dependabot;
const policy = job.steps.find((step) => step.id === 'policy');
const waitForCI = job.steps.find((step) => step.name === 'Wait for checked commit CI');
const token = job.steps.find((step) => step.id === 'app-token');
const merge = job.steps.find((step) => step.env?.GH_TOKEN === '${{ steps.app-token.outputs.token }}');
const scratch = join(root, '.tmp');
mkdirSync(scratch, { recursive: true });
const fixture = mkdtempSync(join(scratch, 'dependabot-auto-merge-fixture-'));
const bin = join(fixture, 'bin');
mkdirSync(bin);
const receipt = {
  workflowSHA256: createHash('sha256').update(workflowText).digest('hex'),
  cases: [],
};
const env = { PATH: bin + ':' + process.env.PATH, HOME: fixture, LC_ALL: 'C' };

function check(name, run) {
  const entry = { name, passed: false };
  receipt.cases.push(entry);
  try {
    run();
    entry.passed = true;
  } catch (error) {
    entry.failure = error.message;
    process.exitCode = 1;
  }
  console.log((entry.passed ? 'PASS ' : 'FAIL ') + name);
}

function shell(script, extraEnv) {
  const result = spawnSync('bash', ['--noprofile', '--norc', '-e', '-o', 'pipefail', '-c', script], {
    cwd: fixture, env: { ...env, ...extraEnv }, encoding: 'utf8',
  });
  assert.ifError(result.error);
  return result;
}

function dependency(overrides = {}) {
  return {
    dependencyName: 'example.test/library', packageEcosystem: 'go_modules',
    directory: '/', dependencyType: 'direct:production',
    updateType: 'version-update:semver-patch', ...overrides,
  };
}

function evaluate(metadata, commits = '1') {
  const output = join(fixture, 'output');
  writeFileSync(output, '');
  const result = shell(policy.run, {
    GITHUB_OUTPUT: output, PR_COMMITS: commits,
    UPDATED_DEPENDENCIES: typeof metadata === 'string' ? metadata : JSON.stringify(metadata),
  });
  return { ...result, output: readFileSync(output, 'utf8') };
}

try {
  check('only trusted, same-repository, non-draft Dependabot PRs target main', () => {
    assert.deepEqual(workflow.on, {
      pull_request_target: { branches: ['main'], types: ['opened', 'synchronize', 'reopened', 'ready_for_review'] },
    });
    assert.equal(job.if.replace(/\s+/g, ' ').trim(), [
      "github.repository == 'Forgeplane-io/vaultsmith'",
      "github.event.pull_request.user.login == 'dependabot[bot]'",
      'github.event.pull_request.head.repo.full_name == github.repository',
      '!github.event.pull_request.draft',
    ].join(' && '));
    assert.deepEqual(workflow.permissions, { contents: 'read', 'pull-requests': 'read', actions: 'read' });
    assert.equal(job.permissions, undefined);
    assert.deepEqual(job.steps.filter((step) => step.uses).map((step) => step.uses.split('@')[0]),
      ['dependabot/fetch-metadata', 'actions/create-github-app-token']);
    for (const step of job.steps) {
      if (step.uses) assert.match(step.uses, /@[a-f0-9]{40}$/);
      if (step.run) assert.equal(step.run.includes('${{'), false, 'No expression interpolation in shell code');
    }
    const metadata = job.steps.find((step) => step.id === 'metadata');
    assert.deepEqual(metadata.with, { 'github-token': '${{ github.token }}' });
    assert.equal(policy.env.PR_COMMITS, '${{ github.event.pull_request.commits }}');
    assert.equal(policy.env.UPDATED_DEPENDENCIES, '${{ steps.metadata.outputs.updated-dependencies-json }}');
  });

  for (const updateType of ['version-update:semver-patch', 'version-update:semver-minor']) {
    for (const packageEcosystem of ['go_modules', 'npm_and_yarn']) {
      check(packageEcosystem + ' application ' + updateType + ' is eligible', () => {
        const result = evaluate([dependency({ updateType, packageEcosystem,
          directory: packageEcosystem === 'go_modules' ? '/' : '/frontend' })]);
        assert.equal(result.status, 0, result.stderr);
        assert.equal(result.output, 'eligible=true\n');
      });
    }
  }

  for (const [name, metadata] of [
    ['major', [dependency({ updateType: 'version-update:semver-major' })]],
    ['mixed patch and major group', [dependency(), dependency({ updateType: 'version-update:semver-major' })]],
    ['API Go tools', [dependency({ directory: '/api' })]],
    ['API TypeScript tools', [dependency({ packageEcosystem: 'npm_and_yarn', directory: '/api/typescript-generator' })]],
    ['frontend development', [dependency({ packageEcosystem: 'npm_and_yarn', directory: '/frontend', dependencyType: 'direct:development' })]],
    ['mixed production/development group', [dependency({ packageEcosystem: 'npm_and_yarn', directory: '/frontend' }), dependency({ packageEcosystem: 'npm_and_yarn', directory: '/frontend', dependencyType: 'direct:development' })]],
    ['GitHub Actions', [dependency({ packageEcosystem: 'github_actions' })]],
    ['container images', [dependency({ packageEcosystem: 'docker' })]],
    ['unknown update type', [dependency({ updateType: '' })]],
    ['empty dependency list', []],
  ]) {
    check(name + ' remains manual', () => {
      const result = evaluate(metadata);
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.output, 'eligible=false\n');
      assert.match(result.stdout, /manual review/i);
    });
  }

  check('additional commits are manual with an explicit verification-budget notice', () => {
    const result = evaluate([dependency()], '2');
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.output, 'eligible=false\n');
    assert.match(result.stdout, /configured=1.*observed=2/);
    assert.match(result.stdout, /recreate.*manual/i);
  });

  for (const metadata of ['', '{', '{}', '[null]']) {
    check('malformed metadata ' + JSON.stringify(metadata) + ' fails without eligibility', () => {
      const result = evaluate(metadata);
      assert.notEqual(result.status, 0);
      assert.equal(result.output, '');
    });
  }

  check('only eligible updates mint a repository-scoped, least-privilege token', () => {
    const eligible = "steps.policy.outputs.eligible == 'true'";
    assert.equal(waitForCI.if, eligible);
    assert.equal(token.if, eligible);
    assert.equal(merge.if, eligible);
    assert.ok(job.steps.indexOf(waitForCI) < job.steps.indexOf(token), 'Mint the App token only after CI');
    assert.deepEqual(token.with, {
      'client-id': '${{ vars.DEPENDABOT_AUTO_MERGE_APP_CLIENT_ID }}',
      'private-key': '${{ secrets.DEPENDABOT_AUTO_MERGE_APP_PRIVATE_KEY }}',
      'permission-contents': 'write', 'permission-pull-requests': 'write',
    });
    assert.deepEqual(merge.env, {
      GH_TOKEN: '${{ steps.app-token.outputs.token }}',
      PR_URL: '${{ github.event.pull_request.html_url }}',
      PR_HEAD_SHA: '${{ github.event.pull_request.head.sha }}',
    });
    assert.deepEqual(waitForCI.env, {
      GH_TOKEN: '${{ github.token }}', GH_REPO: '${{ github.repository }}',
      PR_HEAD_SHA: '${{ github.event.pull_request.head.sha }}',
    });
  });

  writeFileSync(join(bin, 'sleep'), '#!/bin/sh\nprintf "%s\\n" "$@" >> "$SLEEP_ARGS"\n', { mode: 0o755 });
  writeFileSync(join(bin, 'gh'), '#!/bin/sh\n' +
    'if [ "$1" = api ]; then\n' +
    '  printf "%s\\n" "$@" >> "$CI_API_ARGS"\n' +
    '  if [ "$API_STATUS" != 0 ]; then exit "$API_STATUS"; fi\n' +
    '  if [ ! -f "$API_READY" ]; then touch "$API_READY"; exit 0; fi\n' +
    '  printf "42\\n"\n' +
    'else\n' +
    '  printf "%s\\n" "$@" > "$CI_WATCH_ARGS"\n' +
    '  exit "$WATCH_STATUS"\n' +
    'fi\n', { mode: 0o755 });
  for (const [apiStatus, watchStatus] of [['0', '0'], ['0', '1'], ['1', '0']]) {
    check('CI lookup=' + apiStatus + ', watch=' + watchStatus + ' preserves success/failure', () => {
      const prefix = join(fixture, 'ci-' + apiStatus + '-' + watchStatus);
      const sha = 'a'.repeat(40);
      const result = shell(waitForCI.run, {
        GH_TOKEN: 'synthetic-read-token', GH_REPO: 'synthetic/vaultsmith', PR_HEAD_SHA: sha,
        API_STATUS: apiStatus, WATCH_STATUS: watchStatus,
        API_READY: prefix + '-ready', CI_API_ARGS: prefix + '-api',
        CI_WATCH_ARGS: prefix + '-watch', SLEEP_ARGS: prefix + '-sleep',
      });
      assert.equal(result.status, Number(apiStatus) || Number(watchStatus));
      const apiCalls = readFileSync(prefix + '-api', 'utf8').trim().split('\n');
      const expectedCall = ['api', 'repos/synthetic/vaultsmith/actions/workflows/ci.yml/runs?event=pull_request&head_sha=' + sha,
        '--jq', '.workflow_runs[0].id // empty'];
      assert.deepEqual(apiCalls, apiStatus === '0' ? [...expectedCall, ...expectedCall] : expectedCall);
      if (apiStatus === '0') {
        assert.deepEqual(readFileSync(prefix + '-watch', 'utf8').trim().split('\n'),
          ['run', 'watch', '42', '--exit-status', '--compact']);
        assert.equal(readFileSync(prefix + '-sleep', 'utf8'), '3\n');
        assert.match(result.stdout, /Waiting for CI/);
      } else {
        assert.equal(existsSync(prefix + '-watch'), false);
      }
    });
  }

  writeFileSync(join(bin, 'gh'), '#!/bin/sh\n' +
    'printf "%s\\n" "$@" > "$MERGE_ARGS"\n' +
    'exit "$MERGE_STATUS"\n', { mode: 0o755 });
  for (const status of ['0', '1']) {
    check('merge only the checked head, never arm a future head; exit status ' + status, () => {
      const args = join(fixture, 'args');
      const sha = 'a'.repeat(40);
      const url = 'https://github.com/synthetic/vaultsmith/pull/1';
      const result = shell(merge.run, {
        GH_TOKEN: 'synthetic-token', PR_URL: url, PR_HEAD_SHA: sha,
        MERGE_ARGS: args, MERGE_STATUS: status,
      });
      assert.equal(result.status, Number(status));
      assert.deepEqual(readFileSync(args, 'utf8').trim().split('\n'),
        ['pr', 'merge', '--squash', '--match-head-commit', sha, url]);
    });
  }

  check('CI runs this regression check', () => {
    const ci = parse(readFileSync(join(root, '.github/workflows/ci.yml'), 'utf8'));
    assert.ok(ci.jobs['release-snapshot'].steps.some((step) =>
      step.run?.split('\n').includes('node scripts/dependabot-auto-merge-test.cjs')));
  });
} finally {
  rmSync(fixture, { recursive: true, force: true });
  writeFileSync(join(scratch, 'dependabot-auto-merge-test.json'), JSON.stringify(receipt, null, 2) + '\n');
}
