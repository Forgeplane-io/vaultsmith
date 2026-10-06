// Run with node scripts/release-source-test.cjs after npm ci --prefix frontend.
// Executes the checked-in workflow's shell steps against a disposable local origin.
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } = require('node:fs');
const { createRequire } = require('node:module');
const { join } = require('node:path');

const root = join(__dirname, '..');
const frontendRequire = createRequire(join(root, 'frontend/package.json'));
const { parse } = frontendRequire('yaml');
const picomatch = frontendRequire('picomatch');
const workflowText = readFileSync(join(root, '.github/workflows/release.yml'), 'utf8');
const workflow = parse(workflowText);
const scratch = join(root, '.tmp');
mkdirSync(scratch, { recursive: true });
const fixture = mkdtempSync(join(scratch, 'release-source-fixture-'));
const home = join(fixture, 'home');
const bin = join(fixture, 'bin');
const env = {
  PATH: bin + ':' + process.env.PATH,
  HOME: home,
  LC_ALL: 'C',
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_CONFIG_GLOBAL: '/dev/null',
  GIT_AUTHOR_DATE: '2025-01-01T00:00:00Z',
  GIT_COMMITTER_DATE: '2025-01-01T00:00:00Z',
};
const receipt = {
  workflowSHA256: createHash('sha256').update(workflowText).digest('hex'),
  fixtures: {},
  cases: [],
};

function command(program, args, cwd, extraEnv = {}) {
  const result = spawnSync(program, args, { cwd, env: { ...env, ...extraEnv }, encoding: 'utf8' });
  assert.ifError(result.error);
  return result;
}

function git(cwd, ...args) {
  const result = command('git', args, cwd);
  assert.equal(result.status, 0, 'fixture git command failed: ' + args[0]);
  return result.stdout.trim();
}

function check(name, run) {
  const entry = { name };
  receipt.cases.push(entry);
  try {
    run(entry);
    entry.passed = true;
  } catch (error) {
    entry.passed = false;
    entry.failure = error.message;
    process.exitCode = 1;
  }
  console.log((entry.passed ? 'PASS ' : 'FAIL ') + name);
}

const tag = 'v1.2.3';
const seed = join(fixture, 'seed');
const origin = join(fixture, 'origin.git');
const expression = (key) => '$' + '{{ ' + key + ' }}';

try {
  mkdirSync(home);
  mkdirSync(bin);
  git(fixture, 'init', '--quiet', '--initial-branch=main', seed);
  git(seed, 'config', 'user.name', 'Synthetic release fixture');
  git(seed, 'config', 'user.email', 'fixture@example.test');
  git(seed, 'config', 'commit.gpgsign', 'false');
  git(seed, 'config', 'tag.gpgsign', 'false');
  mkdirSync(join(seed, 'scripts'));
  const markerScript = 'printf "%s\\n" "$(cat source.txt)" > "$EXECUTION_MARKER"\n';
  writeFileSync(join(seed, 'source-command.sh'), markerScript);
  writeFileSync(join(seed, 'scripts/verify_release_ci.sh'), markerScript);
  writeFileSync(join(seed, 'source.txt'), 'validated-source\n');
  git(seed, 'add', '.');
  git(seed, 'commit', '--quiet', '-m', 'synthetic validated source');
  const approved = git(seed, 'rev-parse', 'HEAD');
  git(seed, 'tag', '-a', 'fixture-approved', '-m', 'synthetic annotated source');
  writeFileSync(join(seed, 'source.txt'), 'substituted-source\n');
  git(seed, 'commit', '--quiet', '-am', 'synthetic substituted source');
  const substituted = git(seed, 'rev-parse', 'HEAD');
  git(seed, 'tag', '-a', 'fixture-substituted', '-m', 'synthetic annotated source');
  git(fixture, 'clone', '--quiet', '--bare', seed, origin);
  const annotated = {
    [approved]: git(seed, 'rev-parse', 'fixture-approved'),
    [substituted]: git(seed, 'rev-parse', 'fixture-substituted'),
  };
  receipt.fixtures = { tag, approved, substituted, annotated };

  // Only the release lookup is synthetic; validation and Git operations are real.
  writeFileSync(join(bin, 'gh'), '#!/bin/sh\n' +
    'test "$1" = api || exit 1\n' +
    'case "$2" in\n' +
    '  repos/synthetic/vaultsmith/releases/123) printf \'{"tag_name":"v1.2.3","draft":%s}\\n\' "$FIXTURE_DRAFT";;\n' +
    '  repos/synthetic/vaultsmith/releases\\?per_page=100) printf \'[{"tag_name":"v1.2.3","draft":true}]\\n\';;\n' +
    '  *) exit 1;;\n' +
    'esac\n', { mode: 0o755 });

  function setTag(kind, sha) {
    git(fixture, '--git-dir=' + origin, 'update-ref', 'refs/tags/' + tag,
      kind === 'annotated' ? annotated[sha] : sha);
  }

  function expand(value, outputs, event = {}) {
    const values = {
      'needs.validate.outputs.tag': outputs.tag,
      'needs.validate.outputs.version': outputs.version,
      'needs.validate.outputs.sha': outputs.sha,
      'needs.validate.outputs.build_date': outputs.build_date,
      'secrets.GITHUB_TOKEN': 'synthetic-not-a-credential',
      'inputs.tag || github.ref_name': event.inputTag || event.refName,
    };
    return value.replace(/\$\{\{\s*(.*?)\s*\}\}/g, (_, key) => {
      assert.ok(Object.hasOwn(values, key), 'unhandled workflow expression: ' + key);
      assert.notEqual(values[key], undefined, 'missing fixture workflow value: ' + key);
      return values[key];
    });
  }

  function checkout(ref, depth) {
    const directory = mkdtempSync(join(fixture, 'checkout-'));
    git(directory, 'init', '--quiet');
    git(directory, 'remote', 'add', 'origin', origin);
    git(directory, 'fetch', '--quiet', '--no-tags', ...(depth === 0 ? [] : ['--depth=1']), 'origin', ref);
    const commit = git(directory, 'rev-parse', 'FETCH_HEAD^{commit}');
    if (depth === 0) git(directory, 'fetch', '--quiet', '--no-tags', 'origin', 'refs/tags/*:refs/tags/*');
    git(directory, 'checkout', '--quiet', '--detach', commit);
    return directory;
  }

  const validation = workflow.jobs.validate;
  const validateCheckout = validation.steps.find((step) => step.uses?.startsWith('actions/checkout@'));
  const validateStep = validation.steps.find((step) => step.id === 'release');
  let outputs;
  for (const kind of ['lightweight', 'annotated']) {
    for (const event of ['tag-push', 'manual-recovery']) {
      check('validate ' + kind + ' ' + event, (entry) => {
        setTag(kind, approved);
        const manual = event === 'manual-recovery';
        const inputs = { inputTag: manual ? tag : '', refName: manual ? 'main' : tag };
        const directory = checkout(expand(validateCheckout.with.ref, {}, inputs), 0);
        const output = join(directory, 'workflow-output');
        writeFileSync(output, '');
        const result = command('bash', ['-e', '-c', validateStep.run], directory, {
          GITHUB_OUTPUT: output,
          GITHUB_REPOSITORY: 'synthetic/vaultsmith',
          GH_TOKEN: 'synthetic-not-a-credential',
          INPUT_TAG: inputs.inputTag,
          REF_NAME: inputs.refName,
          INPUT_RELEASE_ID: manual ? '123' : '',
          FIXTURE_DRAFT: manual ? 'false' : 'true',
        });
        outputs = Object.fromEntries(readFileSync(output, 'utf8').trim().split('\n').map((line) => {
          const separator = line.indexOf('=');
          return [line.slice(0, separator), line.slice(separator + 1)];
        }));
        entry.exitCode = result.status;
        entry.outputs = outputs;
        assert.equal(result.status, 0, 'validation must succeed');
        assert.deepEqual(outputs, {
          tag, version: '1.2.3', sha: approved,
          build_date: git(seed, 'show', '-s', '--format=%cI', approved),
          release_draft: manual ? 'false' : 'true',
        });
      });
    }
  }

  function jobEnv(job, marker) {
    return {
      ...Object.fromEntries(Object.entries(job.env).map(([key, value]) => [key, expand(value, outputs)])),
      EXECUTION_MARKER: marker,
      GITHUB_SHA: substituted, // A recovery workflow can run at a different commit.
    };
  }

  function executeWithMarker(entry, directory, job, step) {
    const marker = join(directory, 'executed-source');
    const result = command('bash', ['-e', '-c', (step?.run || '') + '\nbash source-command.sh'],
      directory, jobEnv(job, marker));
    entry.head = git(directory, 'rev-parse', 'HEAD');
    entry.exitCode = result.status;
    entry.executedSource = existsSync(marker) ? readFileSync(marker, 'utf8').trim() : null;
    entry.diagnostic = result.stderr.trim();
  }

  for (const name of ['acceptance', 'publish']) {
    const job = workflow.jobs[name];
    const checkoutIndex = job.steps.findIndex((step) => step.uses?.startsWith('actions/checkout@'));
    const checkoutStep = job.steps[checkoutIndex];
    const guard = job.steps[checkoutIndex + 1];
    for (const kind of ['lightweight', 'annotated']) {
      for (const moved of [false, true]) {
        check(name + ' ' + kind + (moved ? ' moved before checkout' : ' stable'), (entry) => {
          setTag(kind, moved ? substituted : approved);
          entry.selectedRef = expand(checkoutStep.with.ref, outputs);
          const directory = checkout(entry.selectedRef, checkoutStep.with['fetch-depth']);
          executeWithMarker(entry, directory, job, guard);
          assert.equal(entry.head, approved, 'downstream checkout must stay on the validated commit');
          assert.equal(entry.exitCode, 0, 'validated source must execute successfully');
          assert.equal(entry.executedSource, 'validated-source', 'only validated source may execute');
        });
      }
    }
    check(name + ' wrong HEAD before source execution', (entry) => {
      setTag('lightweight', approved);
      const directory = checkout(substituted, 0);
      executeWithMarker(entry, directory, job, guard);
      assert.notEqual(entry.exitCode, 0, 'wrong HEAD must abort');
      assert.equal(entry.executedSource, null, 'wrong HEAD must not execute source');
    });
    check(name + ' trusted guard ordering', () => {
      assert.equal(checkoutStep.with.ref, expression('needs.validate.outputs.sha'));
      assert.ok(guard.run?.includes('git rev-parse HEAD'), 'HEAD guard must be inline immediately after checkout');
      assert.equal(guard.if, undefined, 'HEAD guard must be unconditional');
      assert.equal(guard['continue-on-error'], undefined, 'HEAD guard failures must stop the job');
    });
  }

  const publish = workflow.jobs.publish;
  const firstPublication = publish.steps.findIndex((step) => step.run?.includes('goreleaser release'));
  const tagGuard = publish.steps[firstPublication - 1];
  for (const kind of ['lightweight', 'annotated']) {
    for (const state of ['stable', 'moved', 'deleted', 'lookup-failure']) {
      check('publication boundary ' + kind + ' ' + state, (entry) => {
        setTag(kind, approved);
        const directory = checkout(approved, 0);
        if (state === 'moved') setTag(kind, substituted);
        if (state === 'deleted') git(fixture, '--git-dir=' + origin, 'update-ref', '-d', 'refs/tags/' + tag);
        if (state === 'lookup-failure') git(directory, 'remote', 'set-url', 'origin', join(fixture, 'missing-origin.git'));
        executeWithMarker(entry, directory, publish, tagGuard);
        if (state === 'stable') {
          assert.equal(entry.exitCode, 0, 'stable remote tag must permit publication');
          assert.equal(entry.executedSource, 'validated-source');
        } else {
          assert.notEqual(entry.exitCode, 0, 'changed or unresolvable remote tag must abort publication');
          assert.equal(entry.executedSource, null, 'failed tag lookup must not reach publication');
          assert.ok(entry.diagnostic.includes(tag), 'failure must identify the release tag');
          assert.ok(!entry.diagnostic.includes(fixture), 'diagnostics must not expose remote paths');
        }
      });
    }
  }
  check('publication guard covers drafts and manual recovery', () => {
    assert.ok(tagGuard.run?.includes('git ls-remote'), 'remote tag lookup must precede first publication');
    assert.equal(tagGuard.if, undefined, 'publication guard must also run when GoReleaser is skipped');
    assert.equal(tagGuard['continue-on-error'], undefined, 'remote lookup failure must stop publication');
  });

  check('source-bound image metadata and provenance', () => {
    assert.equal(publish.env.SOURCE_SHA, expression('needs.validate.outputs.sha'));
    assert.equal(publish.env.VERSION, expression('needs.validate.outputs.version'));
    assert.equal(publish.env.BUILD_DATE, expression('needs.validate.outputs.build_date'));
    const metadata = publish.steps.find((step) => step.uses?.startsWith('docker/metadata-action@'));
    assert.equal(metadata.with.context, 'git', 'image SHA tags and revision labels must use checkout context');
    const build = publish.steps.find((step) => step.uses?.startsWith('docker/build-push-action@'));
    assert.equal(build.with.context, '.', 'image must build from the pinned working tree');
    assert.ok(build.with['build-args'].includes('COMMIT=' + expression('env.SOURCE_SHA')));
    assert.equal(build.with.provenance, 'mode=max', 'retain BuildKit provenance during recovery');
    const attest = publish.steps.find((step) => step.uses?.startsWith('actions/attest-build-provenance@'));
    assert.equal(attest.if, expression("github.repository_visibility == 'public' && github.sha == needs.validate.outputs.sha"),
      'GitHub event provenance must not attest a different source commit');
  });

  check('CI selects and executes release regressions', () => {
    const filters = parse(readFileSync(join(root, '.github/ci-paths.yml'), 'utf8'));
    for (const path of ['.github/workflows/release.yml', 'scripts/verify_release_ci.sh',
      'scripts/release-source-test.cjs', 'scripts/ci-paths-test.cjs']) {
      assert.ok(picomatch(filters.release_snapshot, { dot: true })(path), 'release snapshot must cover ' + path);
    }
    const ci = parse(readFileSync(join(root, '.github/workflows/ci.yml'), 'utf8'));
    const regression = ci.jobs['release-snapshot'].steps.find((step) => step.run?.includes('node scripts/release-source-test.cjs'));
    assert.ok(regression, 'CI must execute the new regression');
    assert.equal(regression.if, undefined, 'regression must run whenever its CI job is selected');
    assert.equal(regression['continue-on-error'], undefined, 'regression failures must fail CI');
  });
} finally {
  try {
    writeFileSync(join(scratch, 'release-source-test.json'), JSON.stringify(receipt, null, 2) + '\n');
    console.log('Receipt: .tmp/release-source-test.json');
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
}
