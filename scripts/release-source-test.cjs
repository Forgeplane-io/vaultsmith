// Run with node scripts/release-source-test.cjs after npm ci --prefix frontend.
// Executes the checked-in workflow's shell steps against a disposable local origin.
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } = require('node:fs');
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
    'if test "$1" = release && test "$2" = view; then printf \'{"url":"https://release.example.test/v1.2.3"}\\n\'; exit 0; fi\n' +
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
      'steps.image.outputs.digest': event.imageDigest,
      ...(event.chartOutputs === undefined ? {} : {
        ['steps.' + chartStep.id + '.outputs.reference']: event.chartOutputs.reference || '',
      }),
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

  // Execute the actual packaging, signing, and output steps. Registry operations
  // and signing are simulated; packaging and rendering use native Helm.
  const chartStep = publish.steps.find((step) => step.run?.includes('helm push '));
  const helmPath = command('bash', ['-c', 'command -v helm'], root);
  assert.equal(helmPath.status, 0, 'packaged chart regression requires Helm on PATH');
  const realHelm = helmPath.stdout.trim();
  const chartArtifacts = join(scratch, 'release-chart-test');
  mkdirSync(chartArtifacts, { recursive: true });
  const producingDigest = 'sha256:' + 'a'.repeat(64);
  const overrideDigest = 'sha256:' + 'b'.repeat(64);
  const chartDigest = 'sha256:' + 'c'.repeat(64);
  const replacementDigest = 'sha256:' + 'd'.repeat(64);
  const repository = 'ghcr.io/forgeplane-io/vaultsmith';
  const chartRepository = 'oci://registry.example.test/charts';
  const chartReference = chartRepository.slice('oci://'.length) + '/vaultsmith@' + chartDigest;
  const valuesFile = join(chartArtifacts, 'native-values.yaml');
  writeFileSync(valuesFile, `auth:
  mode: native
  csrf:
    existingSecret: synthetic-auth
    key: csrf-secret
  oidc:
    issuerURL: https://idp.example.test/realms/vaultsmith
    clientID: synthetic-vaultsmith
    clientSecret:
      existingSecret: synthetic-auth
      key: oidc-client-secret
    redirectURL: https://vault.example.test/auth/callback
    publicBaseURL: https://vault.example.test
  policy:
    existingConfigMap: synthetic-policy
profiles:
  - id: dev
    label: Development
    passwordEnv: VAULT_PASSWORD_DEV
    passwordSecretKey: dev
secret:
  existingSecret: synthetic-passwords
`);
  receipt.chart = {
    helmVersion: command(realHelm, ['version', '--short'], root).stdout.trim(),
    producingDigest,
    chartDigest,
    replacementDigest,
    registryCallsSimulated: true,
    signingCallsSimulated: true,
    artifacts: '.tmp/release-chart-test',
  };
  const replacementDirectory = join(chartArtifacts, 'tag-replacement');
  mkdirSync(replacementDirectory, { recursive: true });
  const replacementPackage = command(realHelm, ['package', join(root, 'deploy/helm/vaultsmith'),
    '--version', outputs.version, '--app-version', '9.9.9', '--destination', replacementDirectory], root);
  assert.equal(replacementPackage.status, 0, 'synthetic replacement chart packaging must succeed');
  const replacementArchive = join(replacementDirectory, 'vaultsmith-' + outputs.version + '.tgz');
  receipt.chart.replacementArchiveSHA256 = createHash('sha256').update(readFileSync(replacementArchive)).digest('hex');
  writeFileSync(join(bin, 'helm'), `#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == registry && "\${2:-}" == login ]]; then
  printf '%s\\n' "$1" >> "$PUBLICATION_MARKER"
  exit 0
fi
if [[ "$1" == push ]]; then
  printf 'push\\n' >> "$PUBLICATION_MARKER"
  cp "$2" "$FIXTURE_REGISTRY/producing.tgz"
  printf '%s\\n' "$FIXTURE_CHART_DIGEST" > "$FIXTURE_REGISTRY/tag-digest"
  if [[ "$FIXTURE_REGISTRY_STATE" == tag-replaced ]]; then
    printf '%s\\n' "$FIXTURE_REPLACEMENT_DIGEST" > "$FIXTURE_REGISTRY/tag-digest"
  fi
  printf 'Pushed: %s/vaultsmith:%s\\n' "\${3#oci://}" "$VERSION" >&2
  case "$FIXTURE_REGISTRY_STATE" in
    missing-digest) ;;
    short-digest) printf 'Digest: sha256:abcd\\n' >&2;;
    non-hex-digest) printf 'Digest: sha256:%064d\\n' 0 | tr 0 g >&2;;
    duplicate-digest) printf 'Digest: %s\\nDigest: %s\\n' "$FIXTURE_CHART_DIGEST" "$FIXTURE_REPLACEMENT_DIGEST" >&2;;
    *) printf 'Digest: %s\\n' "$FIXTURE_CHART_DIGEST" >&2;;
  esac
  if [[ "$FIXTURE_REGISTRY_STATE" == push-failure ]]; then
    printf 'synthetic push failure\\n' >&2
    exit 42
  fi
  exit 0
fi
if [[ "$1" == pull ]]; then
  printf 'pull\\n' >> "$PUBLICATION_MARKER"
  printf '%s\\n' "$2" > "$FIXTURE_REGISTRY/readback-reference"
  if [[ "$FIXTURE_REGISTRY_STATE" == readback-failure ]]; then
    printf 'synthetic readback failure\\n' >&2
    exit 43
  fi
  if [[ "$2" == *@* ]]; then
    digest="\${2##*@}"
  else
    digest="$(cat "$FIXTURE_REGISTRY/tag-digest")"
  fi
  content="$FIXTURE_REGISTRY/producing.tgz"
  if [[ "$digest" != "$FIXTURE_CHART_DIGEST" || "$FIXTURE_REGISTRY_STATE" == readback-content-mismatch ]]; then
    content="$FIXTURE_REPLACEMENT_ARCHIVE"
  fi
  if [[ "$FIXTURE_REGISTRY_STATE" == readback-digest-mismatch ]]; then
    digest="$FIXTURE_REPLACEMENT_DIGEST"
  fi
  test "$3" = --destination
  name="\${2##*/}"
  cp "$content" "$4/\${name%:*}-\${name##*:}.tgz"
  printf 'Pulled: %s\\nDigest: %s\\n' "\${2#oci://}" "$digest" >&2
  exit 0
fi
exec "$REAL_HELM" "$@"
`, { mode: 0o755 });
  writeFileSync(join(bin, 'cosign'), `#!/usr/bin/env bash
set -euo pipefail
test "$1" = sign
reference="\${@: -1}"
if [[ "$reference" == *@* ]]; then
  digest="\${reference##*@}"
else
  digest="$(cat "$FIXTURE_REGISTRY/tag-digest")"
fi
printf '%s %s\\n' "$reference" "$digest" >> "$SIGNING_MARKER"
`, { mode: 0o755 });

  function packageChart(imageDigest, legacyHelper, registryState = 'normal') {
    const directory = mkdtempSync(join(fixture, 'chart-package-'));
    const source = join(directory, 'deploy/helm/vaultsmith');
    mkdirSync(join(directory, 'deploy/helm'), { recursive: true });
    cpSync(join(root, 'deploy/helm/vaultsmith'), source, { recursive: true });
    if (legacyHelper !== undefined) {
      writeFileSync(join(source, 'templates/_helpers.tpl'), legacyHelper);
    }
    const marker = join(directory, 'publication-marker');
    const output = join(directory, 'chart-output');
    const registry = join(directory, 'registry');
    mkdirSync(registry);
    writeFileSync(output, '');
    const stepEnv = Object.fromEntries(Object.entries(chartStep.env || {})
      .map(([key, value]) => [key, expand(value, outputs, { imageDigest })]));
    const publicationEnv = {
      ...jobEnv(publish, marker), ...stepEnv,
      REAL_HELM: realHelm, PUBLICATION_MARKER: marker,
      GITHUB_OUTPUT: output, SIGNING_MARKER: join(directory, 'signing-marker'),
      GITHUB_STEP_SUMMARY: join(directory, 'summary'),
      FIXTURE_REGISTRY: registry, FIXTURE_REGISTRY_STATE: registryState,
      FIXTURE_CHART_DIGEST: chartDigest, FIXTURE_REPLACEMENT_DIGEST: replacementDigest,
      FIXTURE_REPLACEMENT_ARCHIVE: replacementArchive,
      GITHUB_REPOSITORY: 'synthetic/vaultsmith',
      GITHUB_ACTOR: 'synthetic-fixture', IMAGE: repository, CHART_REPOSITORY: chartRepository,
    };
    const result = command('bash', ['-e', '-c', expand(chartStep.run, outputs, { imageDigest })], directory, publicationEnv);
    const chartOutputs = Object.fromEntries(readFileSync(output, 'utf8').split('\n').filter(Boolean)
      .map((line) => line.split('=')));
    return { result, directory, marker, source, publicationEnv, chartOutputs,
      archive: join(directory, 'dist/chart/vaultsmith-' + outputs.version + '.tgz') };
  }

  function executeSigningAndOutputs(packaged, entry) {
    entry.exitCode = packaged.result.status;
    entry.diagnostic = packaged.result.stderr.trim();
    entry.chartOutputs = packaged.chartOutputs;
    const readback = join(packaged.publicationEnv.FIXTURE_REGISTRY, 'readback-reference');
    entry.readbackReference = existsSync(readback) ? readFileSync(readback, 'utf8').trim() : null;
    entry.signedArtifacts = [];
    if (packaged.result.status !== 0) return;
    const event = { imageDigest: producingDigest, chartOutputs: packaged.chartOutputs };
    const signStep = publish.steps.find((step) => step.run?.includes('cosign sign --yes'));
    const signEnv = Object.fromEntries(Object.entries(signStep.env || {})
      .map(([key, value]) => [key, expand(value, outputs, event)]));
    const signed = command('bash', ['-e', '-c', expand(signStep.run, outputs, event)], packaged.directory,
      { ...packaged.publicationEnv, ...signEnv });
    entry.signExitCode = signed.status;
    const signingMarker = packaged.publicationEnv.SIGNING_MARKER;
    if (existsSync(signingMarker)) {
      entry.signedArtifacts = readFileSync(signingMarker, 'utf8').trim().split('\n').map((line) => {
        const [reference, digest] = line.split(' ');
        return { reference, digest };
      });
    }
    const verifyStep = publish.steps.find((step) => step.name === 'Verify release outputs');
    const verifyEnv = Object.fromEntries(Object.entries(verifyStep.env || {})
      .map(([key, value]) => [key, expand(value, outputs, event)]));
    const verified = command('bash', ['-e', '-c', expand(verifyStep.run, outputs, event)], packaged.directory,
      { ...packaged.publicationEnv, ...verifyEnv });
    entry.verifyExitCode = verified.status;
    entry.releaseOutput = verified.stdout.trim();
    entry.releaseSummary = readFileSync(packaged.publicationEnv.GITHUB_STEP_SUMMARY, 'utf8').trim();
  }

  const packaged = packageChart(producingDigest);
  const archive = join(chartArtifacts, 'vaultsmith-' + outputs.version + '.tgz');
  check('package chart with synthetic build-push digest', (entry) => {
    entry.exitCode = packaged.result.status;
    assert.equal(packaged.result.status, 0, 'workflow chart packaging must succeed');
    cpSync(packaged.archive, archive);
    entry.archiveSHA256 = createHash('sha256').update(readFileSync(archive)).digest('hex');
    assert.deepEqual(readFileSync(packaged.marker, 'utf8').trim().split('\n'), ['registry', 'push', 'pull']);
    for (const file of ['Chart.yaml', 'values.yaml']) {
      assert.equal(readFileSync(join(packaged.source, file), 'utf8'),
        readFileSync(join(root, 'deploy/helm/vaultsmith', file), 'utf8'), 'packaging must not mutate source ' + file);
    }
    const chart = command(realHelm, ['show', 'chart', archive], root);
    assert.equal(chart.status, 0, 'packaged chart metadata must be readable');
    const metadata = parse(chart.stdout);
    assert.equal(metadata.version, outputs.version, 'chart version must stay release-managed');
    assert.equal(metadata.appVersion, outputs.version, 'appVersion must remain the release version');
  });

  // Recovery preserves the tagged source helper, not the workflow's newer one.
  // CI fetches full history so this immutable pre-change fixture is available.
  const legacyHelperRef = 'fabb2f39bb87f5dc36e3f23c3b629b083901d7ef:deploy/helm/vaultsmith/templates/_helpers.tpl';
  const legacyHelper = git(root, 'show', legacyHelperRef) + '\n';
  const legacyPackaged = packageChart(producingDigest, legacyHelper);
  const legacyArchive = join(chartArtifacts, 'older-helper-vaultsmith-' + outputs.version + '.tgz');
  check('package recovery chart with historical helper', (entry) => {
    entry.helperSource = legacyHelperRef;
    entry.exitCode = legacyPackaged.result.status;
    assert.equal(legacyPackaged.result.status, 0, 'older-source recovery packaging must remain supported');
    assert.equal(readFileSync(join(legacyPackaged.source, 'templates/_helpers.tpl'), 'utf8'), legacyHelper,
      'recovery must not replace the tagged source helper');
    cpSync(legacyPackaged.archive, legacyArchive);
    entry.archiveSHA256 = createHash('sha256').update(readFileSync(legacyArchive)).digest('hex');
    const chart = command(realHelm, ['show', 'chart', legacyArchive], root);
    assert.equal(chart.status, 0, 'recovery archive metadata must be readable');
    const metadata = parse(chart.stdout);
    assert.equal(metadata.version, outputs.version);
    assert.equal(metadata.appVersion, outputs.version);
    assert.equal(metadata.annotations['vaultsmith.io/image-digest'], producingDigest,
      'the annotation alone does not prove the historical helper consumes it');
  });

  for (const [name, publishedChart] of [
    ['normal release', packaged], ['historical-source recovery', legacyPackaged],
    ['tag replaced after push', packageChart(producingDigest, undefined, 'tag-replaced')],
  ]) {
    check('chart manifest binding ' + name, (entry) => {
      executeSigningAndOutputs(publishedChart, entry);
      assert.equal(entry.exitCode, 0, 'producing chart push and readback must succeed');
      assert.equal(entry.signExitCode, 0, 'digest signing must succeed');
      assert.deepEqual(entry.signedArtifacts, [
        { reference: repository + '@' + producingDigest, digest: producingDigest },
        { reference: chartReference, digest: chartDigest },
      ], 'sign only the producing image and chart digests, never the replacement tag');
      assert.equal(entry.readbackReference, 'oci://' + chartReference, 'read back the producing manifest without a tag lookup');
      assert.equal(entry.chartOutputs.reference, chartReference, 'retain the verified chart manifest reference');
      assert.equal(entry.verifyExitCode, 0);
      assert.ok(entry.releaseOutput.includes('chart=' + chartReference), 'release output must identify the immutable chart');
      assert.ok(entry.releaseSummary.includes(chartReference), 'summary must identify the immutable chart');
      assert.ok(entry.releaseSummary.includes(repository + '@' + producingDigest), 'summary must retain the producing image');
    });
  }
  for (const [state, diagnostic] of [
    ['push-failure', 'push'], ['missing-digest', 'manifest digest'],
    ['short-digest', 'manifest digest'], ['non-hex-digest', 'manifest digest'],
    ['duplicate-digest', 'manifest digest'], ['readback-failure', 'readback'],
    ['readback-digest-mismatch', 'readback'], ['readback-content-mismatch', 'readback'],
  ]) {
    check('chart manifest binding rejects ' + state, (entry) => {
      const rejected = packageChart(producingDigest, undefined, state);
      executeSigningAndOutputs(rejected, entry);
      assert.notEqual(entry.exitCode, 0, 'invalid or unverifiable producer identity must abort');
      assert.deepEqual(entry.chartOutputs, {}, 'do not export an unverified chart reference');
      assert.deepEqual(entry.signedArtifacts, [], 'failed chart verification must not reach signing');
      assert.ok(entry.diagnostic.includes(diagnostic), 'failure must identify the operation');
      assert.ok(!entry.diagnostic.includes('synthetic-not-a-credential'), 'diagnostics must not expose credentials');
    });
  }

  for (const [name, overrides, expected, chartArchive = archive] of [
    ['default', [], repository + '@' + producingDigest],
    ['tag', ['--set-string', 'image.tag=v4.5.6'], repository + ':v4.5.6'],
    ['digest', ['--set-string', 'image.digest=' + overrideDigest], repository + '@' + overrideDigest],
    ['both', ['--set-string', 'image.tag=v4.5.6,image.digest=' + overrideDigest], repository + '@' + overrideDigest],
    ['repository', ['--set-string', 'image.repository=registry.example.test/synthetic/vaultsmith'],
      'registry.example.test/synthetic/vaultsmith@' + producingDigest],
    ['empty', ['--set-string', 'image.tag=,image.digest='], repository + '@' + producingDigest],
    ['tag-cleared-digest', ['--set-string', 'image.tag=v4.5.6,image.digest='], repository + ':v4.5.6'],
    ['older-helper-default', [], repository + ':' + outputs.version, legacyArchive],
    ['older-helper-digest', ['--set-string', 'image.digest=' + producingDigest],
      repository + '@' + producingDigest, legacyArchive],
  ]) {
    check('packaged chart image ' + name, (entry) => {
      const rendered = command(realHelm, ['template', 'vaultsmith', chartArchive, '-f', valuesFile,
        '--show-only', 'templates/deployment.yaml', ...overrides], root);
      assert.equal(rendered.status, 0, 'packaged chart render must succeed');
      writeFileSync(join(chartArtifacts, name + '.yaml'), rendered.stdout);
      const deployment = parse(rendered.stdout);
      assert.equal(deployment.kind, 'Deployment');
      const containers = deployment.spec.template.spec.containers.filter((container) => container.name === 'vaultsmith');
      assert.equal(containers.length, 1, 'assert the Vaultsmith container, not bundled Valkey');
      entry.image = containers[0].image;
      entry.expectedImage = expected;
      assert.equal(entry.image, expected);
    });
  }
  for (const [name, digest] of [
    ['missing', ''], ['short', 'sha256:abcd'], ['non-hex', 'sha256:' + 'g'.repeat(64)],
  ]) {
    check('chart packaging rejects ' + name + ' producing digest', (entry) => {
      const invalid = packageChart(digest);
      entry.exitCode = invalid.result.status;
      entry.reachedPublication = existsSync(invalid.marker);
      assert.notEqual(invalid.result.status, 0, 'invalid producing digest must abort packaging');
      assert.ok(!existsSync(invalid.archive), 'invalid digest must not produce a release chart');
      assert.equal(entry.reachedPublication, false, 'invalid digest must fail before registry login/push');
      assert.ok(invalid.result.stderr.includes('IMAGE_DIGEST'), 'failure must identify the missing/invalid digest input');
    });
  }
  check('chart workflow consumes producing build-push digest', () => {
    assert.equal(chartStep.env?.IMAGE_DIGEST, expression('steps.image.outputs.digest'));
    assert.equal(chartStep.if, undefined, 'digest binding must also run for manual recovery');
    assert.equal(chartStep['continue-on-error'], undefined, 'chart binding failure must stop publication');
  });

  check('CI selects and executes release regressions', () => {
    const filters = parse(readFileSync(join(root, '.github/ci-paths.yml'), 'utf8'));
    for (const path of ['.github/workflows/release.yml', 'scripts/verify_release_ci.sh',
      'scripts/release-source-test.cjs', 'scripts/ci-paths-test.cjs',
      'deploy/helm/vaultsmith/Chart.yaml', 'deploy/helm/vaultsmith/values.yaml',
      'deploy/helm/vaultsmith/templates/_helpers.tpl']) {
      assert.ok(picomatch(filters.release_snapshot, { dot: true })(path), 'release snapshot must cover ' + path);
    }
    const ci = parse(readFileSync(join(root, '.github/workflows/ci.yml'), 'utf8'));
    const regression = ci.jobs['release-snapshot'].steps.find((step) => step.run?.includes('node scripts/release-source-test.cjs'));
    assert.ok(regression, 'CI must execute the new regression');
    assert.equal(regression.if, undefined, 'regression must run whenever its CI job is selected');
    assert.equal(regression['continue-on-error'], undefined, 'regression failures must fail CI');
    const ciHelm = ci.jobs['release-snapshot'].steps.find((step) => step.uses?.startsWith('azure/setup-helm@'));
    const releaseHelm = publish.steps.find((step) => step.uses?.startsWith('azure/setup-helm@'));
    assert.equal(ciHelm?.with.version, releaseHelm.with.version, 'packaging regression must use release-selected Helm');
    assert.equal(receipt.chart.helmVersion.split('+')[0], releaseHelm.with.version,
      'native regression must run with release-selected Helm');
    for (const job of Object.values(ci.jobs)) {
      for (const step of job.steps || []) {
        if (step.uses?.startsWith('azure/setup-helm@')) {
          assert.equal(step.with.version, releaseHelm.with.version, 'all CI Helm versions must match release Helm');
        }
      }
    }
  });
} finally {
  try {
    writeFileSync(join(scratch, 'release-source-test.json'), JSON.stringify(receipt, null, 2) + '\n');
    console.log('Receipt: .tmp/release-source-test.json');
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
}
