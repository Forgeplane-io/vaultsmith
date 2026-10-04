import { spawn } from 'node:child_process'
import { createServer } from 'node:http'
import { generateKeyPairSync } from 'node:crypto'
import { mkdtemp, writeFile, rm } from 'node:fs/promises'
import { resolve, join } from 'node:path'
import { tmpdir } from 'node:os'
import assert from 'node:assert/strict'

const phase = process.argv[2]
assert.ok(['before', 'after'].includes(phase))
const root = resolve('.tmp/issue-107-evidence')
const temporary = await mkdtemp(join(tmpdir(), 'vaultsmith-107-'))
const children = []
const checks = []
const outcomes = []
const pending = new Map()
let socket, proxy, pageLoaded, nextID = 0, scenario = 'forbidden', profileRequests = 0, verificationOutcome, catalogOutcome
const keyFile = join(temporary, 'keyring.json')
const key = generateKeyPairSync('ed25519').privateKey.export({ format: 'jwk' })
await writeFile(keyFile, JSON.stringify({ version: 1, active: 'synthetic-ui', keys: [{
  id: 'synthetic-ui', state: 'active', publicKey: key.x, privateKey: key.d,
}] }), { mode: 0o600 })
async function listen(server) {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  return `http://127.0.0.1:${server.address().port}`
}
function cdp(method, params = {}) {
  return new Promise((resolve, reject) => {
    const id = ++nextID
    pending.set(id, { resolve, reject })
    socket.send(JSON.stringify({ id, method, params }))
  })
}
async function evaluate(expression) {
  const result = await cdp('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true })
  if (result.exceptionDetails) throw new Error('Browser fixture expression failed: ' + result.exceptionDetails.exception?.description)
  return result.result.value
}
async function until(expression) {
  // Reuse the prior rendered-evidence stalled-capture tripwire: not an application budget.
  await evaluate(`new Promise((resolve, reject) => { const start = performance.now(); function check() { if (${expression}) resolve(true); else if (performance.now() - start > 30000) reject(new Error('Capture budget 30000ms exceeded; increase only for measured slow hosts')); else requestAnimationFrame(check); } check(); })`)
}
async function click(selector) { await evaluate(`document.querySelector(${JSON.stringify(selector)}).click()`) }
async function fill(selector, text) {
  await evaluate(`document.querySelector(${JSON.stringify(selector)}).focus()`)
  await cdp('Input.insertText', { text })
}
async function screenshot(name) {
  // Let Chrome repaint after the previous full-page capture before reading its surface again.
  await evaluate('document.fonts.ready.then(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))))')
  const { cssContentSize } = await cdp('Page.getLayoutMetrics')
  const result = await cdp('Page.captureScreenshot', { captureBeyondViewport: true,
    clip: { x: 0, y: 0, width: cssContentSize.width, height: cssContentSize.height, scale: 1 },
  })
  await writeFile(resolve(root, `${phase}-${name}.png`), Buffer.from(result.data, 'base64'))
}
async function check(name, expression, required = phase === 'after') {
  const passed = Boolean(await evaluate(expression))
  checks.push({ name, passed })
  if (required) assert.equal(passed, true, name)
}
try {
  const reservation = createServer()
  const backendURL = await listen(reservation)
  await new Promise(resolve => reservation.close(resolve))
  proxy = createServer(async (req, res) => {
    try {
      if (req.url === '/api/v1/profiles') {
        profileRequests++
        if (scenario !== 'catalog') {
          res.writeHead(scenario === 'forbidden' ? 403 : 200, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify(scenario === 'forbidden'
            ? { error: { code: 'forbidden', message: 'synthetic-sensitive-detail' } }
            : { profiles: [] }))
          return
        }
      }
      const chunks = []
      for await (const chunk of req) chunks.push(chunk)
      const response = await fetch(backendURL + req.url, {
        method: req.method, headers: { ...req.headers, 'accept-encoding': 'identity' },
        body: chunks.length ? Buffer.concat(chunks) : undefined,
      })
      const body = Buffer.from(await response.arrayBuffer())
      if (req.url === '/api/v1/attestations/verify') {
        verificationOutcome = { status: response.status, valid: JSON.parse(body).valid }
      }
      if (req.url === '/api/v1/profiles') {
        catalogOutcome = { status: response.status, profileIds: JSON.parse(body).profiles.map(profile => profile.id) }
      }
      res.writeHead(response.status, Object.fromEntries(response.headers))
      res.end(body)
    } catch { res.writeHead(502); res.end('Synthetic fixture proxy failed') }
  })
  const url = await listen(proxy)
  const server = spawn(resolve(root, `${phase}-server`), [], { stdio: 'ignore', env: {
    ...process.env, AUTH_MODE: 'off', COOKIE_SECURE: 'false', HTTP_ADDR: backendURL.slice(7),
    PROOFS_ENABLED: 'true', PROOFS_KEYRING_FILE: keyFile, PUBLIC_BASE_URL: 'https://vaultsmith.example.test', CORS_ALLOWED_ORIGINS: url,
    VAULT_PROFILES_JSON: JSON.stringify([
      { id: 'dev', label: 'Synthetic development', passwordEnv: 'VAULT_PASSWORD_DEV' },
      { id: 'prod', label: 'Synthetic production', passwordEnv: 'VAULT_PASSWORD_PROD' },
    ]), VAULT_PASSWORD_DEV: 'synthetic-source-password', VAULT_PASSWORD_PROD: 'synthetic-destination-password',
  } })
  children.push(server)
  for (;;) {
    if (server.exitCode !== null) throw new Error('Loopback fixture server failed startup')
    try { if ((await fetch(`${backendURL}/readyz`)).ok) break } catch {}
    await new Promise(resolve => setTimeout(resolve, 50))
  }
  async function api(path, body) {
    const response = await fetch(backendURL + path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
    assert.equal(response.status, 200, path)
    return response.json()
  }
  const original = (await api('/api/v1/profiles/dev/encrypt', { plaintext: 'synthetic-issue-107' })).vaultText
  const rotated = await api('/api/v1/rotations', { sourceProfileId: 'dev', destinationProfileId: 'prod', vaultText: original, attestation: {} })
  const chrome = spawn('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', [
    '--headless=new', '--no-first-run', '--no-default-browser-check', '--disable-background-networking',
    '--remote-debugging-port=0', '--remote-debugging-address=127.0.0.1', `--user-data-dir=${join(temporary, 'chrome')}`, 'about:blank',
  ], { stdio: ['ignore', 'ignore', 'pipe'] })
  children.push(chrome)
  const browserSocket = await new Promise((resolve, reject) => {
    chrome.once('exit', () => reject(new Error('Headless browser failed startup')))
    chrome.stderr.on('data', data => { const match = data.toString().match(/DevTools listening on (ws:\/\/\S+)/); if (match) resolve(match[1]) })
  })
  const targets = await (await fetch(`http://${new URL(browserSocket).host}/json/list`)).json()
  socket = new WebSocket(targets.find(target => target.type === 'page').webSocketDebuggerUrl)
  await new Promise(resolve => socket.addEventListener('open', resolve, { once: true }))
  socket.addEventListener('message', event => {
    const response = JSON.parse(event.data)
    if (response.method === 'Page.loadEventFired') pageLoaded?.()
    const request = pending.get(response.id)
    if (!request) return
    pending.delete(response.id)
    if (response.error) request.reject(new Error(response.error.message))
    else request.resolve(response.result)
  })
  await cdp('Page.enable')
  await cdp('Runtime.enable')
  const browser = await cdp('Browser.getVersion')
  async function reset(nextScenario) {
    scenario = nextScenario
    profileRequests = 0
    verificationOutcome = undefined
    catalogOutcome = undefined
    const loaded = new Promise(resolve => { pageLoaded = resolve })
    await cdp('Page.navigate', { url })
    await loaded
    await until(`document.querySelector('[aria-label="Set verify mode"]')?.disabled === false && !document.querySelector('[role=status]')`)
    assert.equal(profileRequests, 1)
  }
  async function verify() {
    await click('[aria-label="Set verify mode"]')
    await fill('#verification-attestation', JSON.stringify(rotated.attestation))
    await fill('#verification-input', original)
    await fill('#verification-output', rotated.vaultText)
    await check('Standalone Verify enabled', '!document.querySelector("button[type=submit]").disabled', true)
    await click('button[type="submit"]')
    await until(`document.querySelector('[aria-label="Verification result"]')?.textContent.includes('Verified')`)
    assert.deepEqual(verificationOutcome, { status: 200, valid: true })
  }
  for (const [viewport, width, height] of [['desktop', 1440, 1000], ['narrow', 390, 844]]) {
    await cdp('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile: false })
    await reset('forbidden')
    await screenshot(`discovery-failure-${viewport}`)
    await check(`${viewport}: safe discovery error and Retry`, 'document.querySelector("[role=alert]")?.textContent.includes("Profiles could not be loaded.") && document.querySelector("[role=alert] button")?.textContent === "Retry loading environments"')
    await check(`${viewport}: sensitive server detail suppressed`, '!document.body.textContent.includes("synthetic-sensitive-detail")', true)
    await verify()
    outcomes.push({ viewport, fixture: '403', verificationOutcome })
    await screenshot(`standalone-verify-${viewport}`)
    await check(`${viewport}: discovery Retry retained after native Verify`, 'document.querySelector("[role=alert] button")?.textContent === "Retry loading environments"')
    scenario = 'catalog'
    const retryAvailable = await evaluate('Boolean(document.querySelector("[role=alert] button"))')
    if (retryAvailable) {
      await click('[role="alert"] button')
      await until('!document.querySelector("[role=alert]") && !document.querySelector("[role=status]")')
      assert.deepEqual(catalogOutcome, { status: 200, profileIds: ['dev', 'prod'] })
      await click('[aria-label="Set encrypt mode"]')
    }
    await screenshot(`recovery-${viewport}`)
    await check(`${viewport}: user Retry recovers native profiles`, `document.querySelector('#profile-select')?.value === 'dev' && !document.querySelector('[aria-label="Set encrypt mode"]').disabled && !document.querySelector('[role=alert]')`)
    outcomes.push({ viewport, fixture: 'retry', retryAvailable, nativeCatalogRequested: profileRequests === 2, catalogOutcome })
    await reset('empty')
    await verify()
    await check(`${viewport}: 200 empty catalog has no discovery error`, '!document.querySelector("[role=alert]")', true)
    outcomes.push({ viewport, fixture: '200 empty', verificationOutcome })
    await screenshot(`empty-catalog-verify-${viewport}`)
  }
  await writeFile(resolve(root, `${phase}-receipt.json`), JSON.stringify({
    phase, source: process.argv[3], browser: browser.product, route: '/', role: 'loopback-only auth-off synthetic operator',
    viewports: ['1440x1000', '390x844'], fixtures: 'Native encryption/rotation/Verify; discovery-only proxy injects 403 or 200 empty; Retry forwards native catalog',
    checks, outcomes,
  }, null, 2))
  console.log(`${phase}: ${checks.filter(check => check.passed).length}/${checks.length} UI expectations; native Verify passed in all four flows`)
} finally {
  socket?.close()
  for (const child of children) { child.kill(); if (child.exitCode === null) await new Promise(resolve => child.once('exit', resolve)) }
  proxy?.closeAllConnections()
  if (proxy) await new Promise(resolve => proxy.close(resolve))
  await rm(temporary, { recursive: true, force: true })
}
