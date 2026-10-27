// Concrete native delegated re-key acceptance. Credentials/material stay in the
// disposable harness context; only bounded status/boolean receipts are retained.
import { spawn, execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { readFile, writeFile, rename, stat, utimes, mkdir, rm } from 'node:fs/promises'
import { dirname, resolve, join } from 'node:path'
import https from 'node:https'
import { setTimeout as sleep } from 'node:timers/promises'

const root = resolve(import.meta.dirname, '..')
const contextFile = process.env.VAULTSMITH_NATIVE_CONTEXT
if (!contextFile) throw new Error('private native context is required')
const fixture = JSON.parse(await readFile(contextFile, 'utf8'))
const privateDirectory = dirname(contextFile)
const profileDirectory = join(privateDirectory, 'chrome-profile')
const artifactDirectory = join(root, '.tmp/delegated-rekey-step6')
await mkdir(artifactDirectory, { recursive: true })
const hash = createHash('sha256').update(execFileSync('git', ['diff', '--binary', '--'], { cwd: root }))
for (const name of ['scripts/integration_native_test.py', 'integration/docker-compose.linux.yml', 'integration/Caddyfile-linux', 'integration/delegated-rekey-browser.mjs']) {
  hash.update(name + '\0').update(await readFile(join(root, name)))
}
const identity = { source_revision: execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root }).toString().trim(), source_diff_sha256: hash.digest('hex') }
if (fixture.identity?.source_revision !== identity.source_revision || fixture.identity?.source_diff_sha256 !== identity.source_diff_sha256) {
  throw new Error('native fixture source identity differs; restart the harness before browser acceptance')
}
const receipts = []
const lifecycle = new AbortController()
const pending = new Map()
function stop(message) {
  if (lifecycle.signal.aborted) return
  lifecycle.abort(new Error(message))
  for (const waiting of pending.values()) waiting.reject(lifecycle.signal.reason)
  pending.clear()
}
function interrupt() {
  process.exitCode = 1
  stop('browser acceptance interrupted')
}
let current = 'browser-launch'
async function check(scenario, expected, observed) {
  receipts.push({ ...identity, scenario, transport: 'Chrome-session', expected, observed, pass: expected === observed })
  await writeFile(join(artifactDirectory, 'browser.json'), JSON.stringify(receipts, null, 2) + '\n')
  if (expected !== observed) throw new Error('browser acceptance assertion failed')
}
async function progress(name) {
  current = name
  await writeFile(join(privateDirectory, 'browser-progress.json'), JSON.stringify({ scenario: name }))
}
async function waitFor(condition) {
  while (true) {
    lifecycle.signal.throwIfAborted()
    if (await condition()) return
    await sleep(100, undefined, { signal: lifecycle.signal })
  }
}
function privateAPI(path, body) {
  if (!path.startsWith('/api/v1/')) throw new Error('unapproved oracle route')
  return new Promise((resolveRequest, reject) => {
    const request = https.request(new URL(path, fixture.base), { method: 'POST', rejectUnauthorized: false, signal: lifecycle.signal, headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + fixture.ownerToken } }, (response) => {
      const chunks = []
      response.on('data', (chunk) => chunks.push(chunk))
      response.on('end', () => {
        if (response.statusCode !== 200) return reject(new Error('private oracle request failed'))
        try { resolveRequest(JSON.parse(Buffer.concat(chunks))) } catch { reject(new Error('private oracle response invalid')) }
      })
    })
    request.on('error', () => reject(new Error('private oracle transport failed')))
    request.end(JSON.stringify(body))
  })
}
async function removeLane() {
  if (dirname(fixture.policyFile) !== privateDirectory) throw new Error('policy is outside owned fixture')
  const previous = await stat(fixture.policyFile)
  const replacement = fixture.policyFile + '.browser-replacement'
  await writeFile(replacement, fixture.removedPolicy, { mode: 0o600 })
  const changed = new Date(previous.mtimeMs + 1000)
  await utimes(replacement, changed, changed)
  await rename(replacement, fixture.policyFile)
}

let socket
let chrome
let chromeExit
let send
let evaluate
let navigationViolation = false
process.on('SIGINT', interrupt)
process.on('SIGTERM', interrupt)
try {
  chrome = spawn('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', ['--user-data-dir=' + profileDirectory, '--no-first-run', '--no-default-browser-check', '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0', 'about:blank'], { stdio: 'ignore' })
  chromeExit = new Promise((resolveExit) => {
    chrome.once('error', () => { stop('owned browser could not start'); resolveExit() })
    chrome.once('exit', () => { stop('owned browser exited'); resolveExit() })
  })
  await writeFile(join(privateDirectory, 'chrome.pid'), String(chrome.pid), { mode: 0o600 })
  let activePort
  await waitFor(async () => {
    try { activePort = (await readFile(join(profileDirectory, 'DevToolsActivePort'), 'utf8')).split('\n')[0]; return /^\d+$/.test(activePort) } catch (error) {
      if (error.code === 'ENOENT') return false
      throw new Error('owned DevTools state could not be read')
    }
  })
  const targets = await (await fetch('http://127.0.0.1:' + activePort + '/json/list', { signal: lifecycle.signal })).json()
  const target = targets.find((item) => item.type === 'page' && item.url === 'about:blank')
  if (!target || new URL(target.webSocketDebuggerUrl).hostname !== '127.0.0.1') throw new Error('isolated browser target unavailable')
  socket = new WebSocket(target.webSocketDebuggerUrl)
  await new Promise((resolveOpen, reject) => {
    lifecycle.signal.throwIfAborted()
    pending.set(0, { resolve: resolveOpen, reject })
    socket.addEventListener('open', () => { pending.delete(0); resolveOpen() }, { once: true })
    socket.addEventListener('error', () => stop('local DevTools unavailable'), { once: true })
    socket.addEventListener('close', () => stop('local DevTools closed'), { once: true })
  })
  let sequence = 0
  socket.addEventListener('message', (event) => {
    try {
      const message = JSON.parse(event.data)
      if (message.id) {
        const waiting = pending.get(message.id)
        if (!waiting) return
        pending.delete(message.id)
        if (message.error) waiting.reject(new Error('DevTools command failed'))
        else waiting.resolve(message.result)
      }
      if (message.method === 'Page.frameNavigated' && !message.params.frame.parentId) {
        const url = message.params.frame.url
        if (url !== 'about:blank' && !['https://localhost:18443', 'https://localhost:18081'].includes(new URL(url).origin)) navigationViolation = true
      }
    } catch {
      stop('invalid DevTools message')
    }
  })
  send = (method, params = {}) => new Promise((resolveCommand, reject) => {
    lifecycle.signal.throwIfAborted()
    const id = ++sequence
    pending.set(id, { resolve: resolveCommand, reject })
    socket.send(JSON.stringify({ id, method, params }))
  })
  evaluate = async (expression) => {
    if (navigationViolation) throw new Error('browser navigated outside approved origins')
    const result = await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true })
    if (result.exceptionDetails) throw new Error('browser evaluation failed')
    return result.result.value
  }
  const set = (selector, value) => evaluate(`(() => { const element=document.querySelector(${JSON.stringify(selector)}); if(!element) return false; const prototype=element.tagName==='TEXTAREA'?HTMLTextAreaElement.prototype:element.tagName==='SELECT'?HTMLSelectElement.prototype:HTMLInputElement.prototype; Object.getOwnPropertyDescriptor(prototype,'value').set.call(element,${JSON.stringify(value)}); element.dispatchEvent(new Event(element.tagName==='SELECT'?'change':'input',{bubbles:true})); return true })()`)
  const click = (selector) => evaluate(`(() => { const element=document.querySelector(${JSON.stringify(selector)}); if(!element || element.disabled) return false; element.click(); return true })()`)
  const options = (selector) => evaluate(`Array.from(document.querySelector(${JSON.stringify(selector)}).options).map(option=>option.value).filter(Boolean)`)
  const screenshot = async (name) => {
    if (!(await evaluate(`!document.querySelector('#value-input')?.value && !document.querySelector('#result-output')?.value && !document.querySelector('[aria-label="Attestation JSON"]')`))) throw new Error('refusing material-bearing screenshot')
    const clip = await evaluate(`(() => { const rect=document.querySelector('section.workbench-card').getBoundingClientRect();return {x:rect.x+scrollX,y:rect.y+scrollY,width:rect.width,height:rect.height,scale:1} })()`)
    const capture = await send('Page.captureScreenshot', { format: 'png', clip, captureBeyondViewport: true })
    await writeFile(join(artifactDirectory, name), Buffer.from(capture.data, 'base64'))
  }
  await send('Page.enable')
  await send('Runtime.enable')
  await send('Security.enable')
  await send('Security.setIgnoreCertificateErrors', { ignore: true })
  await send('Emulation.setDeviceMetricsOverride', { width: 1440, height: 1000, deviceScaleFactor: 1, mobile: false })
  await send('Page.addScriptToEvaluateOnNewDocument', { source: `window.__rotationCalls=0;const originalFetch=window.fetch.bind(window);window.fetch=(input,...arguments_)=>{if(new URL(typeof input==='string'?input:input.url,location.href).pathname==='/api/v1/rotations')window.__rotationCalls++;return originalFetch(input,...arguments_)}` })
  await progress('browser-login')
  await send('Page.navigate', { url: fixture.base + '/' })
  await waitFor(() => evaluate(`location.origin==='https://localhost:18081' && !!document.querySelector('#username') && !!document.querySelector('#password')`))
  await set('#username', fixture.username)
  await set('#password', fixture.password)
  await click('#kc-login')
  await waitFor(() => evaluate(`location.origin==='https://localhost:18443' && !!document.querySelector('#source-profile-select')`))
  await check('browser-lane-only-startup', true, await evaluate(`document.querySelector('.console-app')?.dataset.mode==='rotate' && document.querySelector('[aria-label="Set encrypt mode"]').disabled && document.querySelector('[aria-label="Set decrypt mode"]').disabled && document.querySelector('[aria-label="Set generate mode"]').disabled`))
  await check('browser-exact-source-options', true, JSON.stringify(await options('#source-profile-select')) === JSON.stringify(['dev', 'stage']))
  await screenshot('native-browser-empty.png')
  await set('#source-profile-select', 'dev')
  await set('#destination-profile-select', 'prod')
  await set('#source-profile-select', 'stage')
  await check('browser-source-change-clears-invalid-destination', true, await evaluate(`document.querySelector('#destination-profile-select').value===''`))
  await check('browser-no-crossed-destinations', true, JSON.stringify(await options('#destination-profile-select')) === JSON.stringify(['archive']))
  await set('#source-profile-select', 'dev')
  await set('#destination-profile-select', 'prod')
  await set('#value-input', fixture.inputVaultText)
  await progress('browser-ordinary-submit')
  await check('browser-ordinary-submit-enabled', true, await click('form[aria-label="Vault operation form"] button[type="submit"]'))
  await waitFor(() => evaluate(`document.querySelector('form[aria-label="Vault operation form"]').getAttribute('aria-busy')==='false' && !!document.querySelector('#result-output').value`))
  let output = await evaluate(`document.querySelector('#result-output').value`)
  let oracle = await privateAPI('/api/v1/profiles/prod/decrypt', { vaultText: output })
  await check('browser-ordinary-server-oracle', true, oracle.plaintext === fixture.expectedPlaintext)
  await click('.attestation-options input[type="checkbox"]')
  await progress('browser-attested-submit')
  await check('browser-attested-submit-enabled', true, await click('form[aria-label="Vault operation form"] button[type="submit"]'))
  await waitFor(() => evaluate(`document.querySelector('form[aria-label="Vault operation form"]').getAttribute('aria-busy')==='false' && !!document.querySelector('[aria-label="Attestation JSON"]')`))
  output = await evaluate(`document.querySelector('#result-output').value`)
  const proof = JSON.parse(await evaluate(`document.querySelector('[aria-label="Attestation JSON"]').value`))
  oracle = await privateAPI('/api/v1/profiles/prod/decrypt', { vaultText: output })
  await check('browser-attested-server-oracle', true, oracle.plaintext === fixture.expectedPlaintext)
  const verified = await privateAPI('/api/v1/attestations/verify', { attestation: proof, inputVaultText: fixture.inputVaultText, outputVaultText: output })
  await check('browser-proof-pair-binding', true, verified.valid && verified.attestation.sourceProfileId === 'dev' && verified.attestation.destinationProfileId === 'prod')
  await progress('browser-owner-removal')
  const before = await evaluate('window.__rotationCalls')
  await removeLane()
  await check('browser-stale-pair-submit', true, await click('form[aria-label="Vault operation form"] button[type="submit"]'))
  await waitFor(() => evaluate(`document.querySelector('form[aria-label="Vault operation form"]').getAttribute('aria-busy')==='false' && Array.from(document.querySelector('#source-profile-select').options).filter(option=>option.value).every(option=>option.value==='stage') && !document.querySelector('[aria-label="Attestation JSON"]')`))
  await check('browser-removal-invalidates-exportable-result', true, await evaluate(`document.querySelector('#result-output').value==='' && document.querySelector('form[aria-label="Vault operation form"] button[type="submit"]').disabled && document.querySelector('#value-input').value.length>0`))
  await evaluate('new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)))')
  await check('browser-no-automatic-replay', before + 1, await evaluate('window.__rotationCalls'))
  await check('browser-clear-after-denial', true, await click('.input-actions .quiet-button'))
  await check('browser-cleared-state', true, await evaluate(`document.querySelector('#value-input').value==='' && document.querySelector('#result-output').value==='' && !document.querySelector('[aria-label="Attestation JSON"]')`))
  await screenshot('native-browser-cleared.png')
  await progress('browser-logout')
  await click('.session-controls button')
  await waitFor(() => evaluate(`!!document.querySelector('#signed-out-heading')`))
  await check('browser-server-logout', true, await evaluate(`fetch('/api/v1/session').then(response=>response.json()).then(session=>session.authenticated===false)`))
  await check('browser-approved-origins-only', false, navigationViolation)
  console.log('Rendered native delegated re-key acceptance: pass')
} catch {
  await check(current, true, false).catch(() => {})
  console.log('Rendered native delegated re-key acceptance: failed at ' + current)
  process.exitCode = 1
} finally {
  stop('browser acceptance closing')
  socket?.close()
  // Cleanup does not depend on a responsive or even established CDP channel.
  // Terminate only the child we spawned, then reap it before removing its profile.
  if (chrome?.pid && chrome.exitCode === null && chrome.signalCode === null) chrome.kill('SIGTERM')
  if (chromeExit) await chromeExit
  await rm(profileDirectory, { recursive: true, force: true })
  await rm(join(privateDirectory, 'chrome.pid'), { force: true })
  process.off('SIGINT', interrupt)
  process.off('SIGTERM', interrupt)
}
