// Black-box process/profile regressions. Only the external Chrome/tool boundary
// is replaced; the checked-in browser acceptance entry point runs unchanged.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { once } from 'node:events'
import { watch, readFileSync } from 'node:fs'
import { mkdtemp, readFile, writeFile, rm, access, mkdir } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

process.umask(0o077)
const root = resolve(import.meta.dirname, '..')
const artifacts = join(root, '.tmp/delegated-rekey-step6')
const results = []
await mkdir(artifacts, { recursive: true })

const preload = `
import { createRequire, syncBuiltinESMExports } from 'node:module'
const require = createRequire(import.meta.url)
const cp = require('node:child_process')
const fs = require('node:fs')
const promises = require('node:fs/promises')
const path = require('node:path')
const directory = process.env.VAULTSMITH_BROWSER_STUB_DIRECTORY
const event = value => fs.appendFileSync(path.join(directory,'events'),JSON.stringify(value)+'\\n')
const spawn = cp.spawn
cp.spawn = (command,args,options) => {
  if (command !== '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome') throw new Error('unapproved test child')
  event({event:'chrome-spawn'})
  const mode = JSON.parse(fs.readFileSync(path.join(directory,'mode.json'))).mode
  const child = mode === 'spawn-error'
    ? spawn(path.join(directory,'nonexistent-browser'),args,options)
    : spawn(process.execPath,[path.join(directory,'chrome-stub.mjs'),...args],options)
  // An event-driven release lets the old failed-handshake finally block finish
  // instead of timing out. It is a failure, never application cleanup evidence.
  const originalOnce = child.once
  child.once = function(name,...listeners) {
    if (name==='exit' && fs.existsSync(path.join(directory,'browser-receipts.json')) && this.exitCode===null && !this.killed) {
      event({event:'test-forced-child-release'})
      this.kill('SIGTERM')
    }
    return originalOnce.call(this,name,...listeners)
  }
  return child
}
const writeFile = promises.writeFile
promises.writeFile = (file,...arguments_) => writeFile(String(file)===path.join(${JSON.stringify(artifacts)},'browser.json')?path.join(directory,'browser-receipts.json'):file,...arguments_)
syncBuiltinESMExports()
`
const stub = `
import { createServer } from 'node:http'
import { createHash } from 'node:crypto'
import { appendFileSync,writeFileSync,mkdirSync,readFileSync } from 'node:fs'
import { join } from 'node:path'
const directory=process.env.VAULTSMITH_BROWSER_STUB_DIRECTORY
const event=value=>appendFileSync(join(directory,'events'),JSON.stringify(value)+'\\n')
const mode=JSON.parse(readFileSync(join(directory,'mode.json'),'utf8')).mode
const profile=process.argv.find(value=>value.startsWith('--user-data-dir=')).slice('--user-data-dir='.length)
mkdirSync(profile,{recursive:true})
let server
const connections=new Set()
process.on('SIGTERM',()=>{event({event:'chrome-terminated'});for(const socket of connections)socket.destroy();server?.close();process.exit(0)})
event({event:'chrome-ready',pid:process.pid})
if(mode==='readiness' || mode==='state-error') {
  if(mode==='state-error')mkdirSync(join(profile,'DevToolsActivePort'))
  server=createServer()
  server.listen(0,'127.0.0.1')
} else {
  server=createServer((request,response)=>{
    response.setHeader('Content-Type','application/json')
    response.end(JSON.stringify([{type:'page',url:'about:blank',webSocketDebuggerUrl:'ws://127.0.0.1:'+server.address().port+'/devtools/page/stub'}]))
  })
  server.on('connection',socket=>{connections.add(socket);socket.on('close',()=>connections.delete(socket))})
  server.on('upgrade',(request,socket)=>{
    if(mode==='handshake-error'){socket.destroy();return}
    const accept=createHash('sha1').update(request.headers['sec-websocket-key']+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64')
    socket.write('HTTP/1.1 101 Switching Protocols\\r\\nUpgrade: websocket\\r\\nConnection: Upgrade\\r\\nSec-WebSocket-Accept: '+accept+'\\r\\n\\r\\n')
    socket.once('data',()=>{
      event({event:'cdp-pending'})
      if(mode==='child-exit')process.exit(1)
      if(mode==='cdp-close')socket.destroy()
      // RFC 6455 unmasked server text frame containing deliberately invalid JSON.
      if(mode==='malformed-cdp')socket.write(Buffer.from([0x81,1,0x7b]))
    })
  })
  server.listen(0,'127.0.0.1',()=>writeFileSync(join(profile,'DevToolsActivePort'),String(server.address().port)+'\\n'))
}
`

function currentIdentity() {
  const hash = createHash('sha256').update(execFileSync('git', ['diff', '--binary', '--'], { cwd: root }))
  for (const name of ['scripts/integration_native_test.py', 'integration/docker-compose.linux.yml', 'integration/Caddyfile-linux', 'integration/delegated-rekey-browser.mjs']) hash.update(name + '\0').update(readFileSync(join(root, name)))
  return { source_revision: execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root }).toString().trim(), source_diff_sha256: hash.digest('hex') }
}
async function exists(file) {
  try { await access(file); return true } catch (error) { if (error.code === 'ENOENT') return false; throw error }
}
function alive(pid) {
  if (!pid) return false
  try { process.kill(pid, 0); return true } catch (error) { if (error.code === 'ESRCH') return false; throw error }
}
async function events(directory) {
  const text = await readFile(join(directory, 'events'), 'utf8')
  return text.split('\n').slice(0, -1).map(line => JSON.parse(line))
}
async function phase(directory, name, exited) {
  while (true) {
    const watcher = watch(directory)
    const changed = once(watcher, 'change')
    try {
      if ((await events(directory)).some(event => event.event === name)) return
      const result = await Promise.race([changed.then(() => 'changed'), exited.then(() => 'exited')])
      if (result === 'exited') throw new Error('acceptance exited before controlled test phase')
    } finally { watcher.close() }
  }
}

async function regression(name, mode, { stale, signal, at } = {}) {
  await test(name, async () => {
    const directory = await mkdtemp(join(tmpdir(), 'vaultsmith-browser-regression-'))
    const profile = join(directory, 'chrome-profile')
    let child
    let exited
    let stubPID
    let result
    try {
      const identity = currentIdentity()
      const fixture = { identity: { ...identity }, base: 'https://localhost:18443' }
      // Keep the identity well-formed: this checks equality, not just syntax.
      if (stale) fixture.identity[stale] = fixture.identity[stale].replace(/^./, character => character === '0' ? '1' : '0')
      await writeFile(join(directory, 'acceptance-context.json'), JSON.stringify(fixture))
      await writeFile(join(directory, 'mode.json'), JSON.stringify({ mode }))
      await writeFile(join(directory, 'events'), '')
      await writeFile(join(directory, 'preload.mjs'), preload)
      await writeFile(join(directory, 'chrome-stub.mjs'), stub)
      child = spawn(process.execPath, ['--import', join(directory, 'preload.mjs'), join(root, 'integration/delegated-rekey-browser.mjs')], { cwd: root, env: { ...process.env, VAULTSMITH_NATIVE_CONTEXT: join(directory, 'acceptance-context.json'), VAULTSMITH_BROWSER_STUB_DIRECTORY: directory }, stdio: ['ignore', 'pipe', 'pipe'] })
      // Drain without printing credential-/path-bearing child diagnostics.
      child.stdout.resume()
      child.stderr.resume()
      exited = once(child, 'exit')
      if (signal) { await phase(directory, at, exited); child.kill(signal) }
      const [code, termination] = await exited
      const observed = await events(directory)
      stubPID = observed.find(event => event.event === 'chrome-ready')?.pid
      result = { scenario: name, transport: 'owned-stub-process', unsuccessful: code !== 0 || termination !== null, chrome_spawned: observed.some(event => event.event === 'chrome-spawn'), child_stopped: !alive(stubPID), profile_removed: !(await exists(profile)), required_test_release: observed.some(event => event.event === 'test-forced-child-release') }
      result.pass = result.unsuccessful && result.child_stopped && result.profile_removed && !result.required_test_release && (!stale || !result.chrome_spawned)
      results.push(result)
      await writeFile(join(artifacts, 'browser-lifecycle-tests.json'), JSON.stringify(results, null, 2) + '\n')
      assert.equal(result.pass, true, 'owned process/profile or pre-launch identity contract failed')
    } finally {
      if (child && child.exitCode === null && child.signalCode === null) { child.kill('SIGTERM'); await exited }
      const observed = await events(directory)
      stubPID ??= observed.find(event => event.event === 'chrome-ready')?.pid
      if (alive(stubPID)) {
        process.kill(stubPID, 'SIGTERM')
        while (alive(stubPID)) await new Promise(resolveTurn => setImmediate(resolveTurn))
      }
      await rm(directory, { recursive: true, force: true })
      assert.equal(await exists(directory), false, 'controlled test directory remains')
      if (result) {
        result.test_cleanup_complete = !alive(stubPID) && !(await exists(directory))
        await writeFile(join(artifacts, 'browser-lifecycle-tests.json'), JSON.stringify(results, null, 2) + '\n')
      }
    }
  })
}

await regression('stale revision rejects before Chrome spawn', 'handshake-error', { stale: 'source_revision' })
await regression('stale diff rejects before Chrome spawn', 'handshake-error', { stale: 'source_diff_sha256' })
await regression('failed WebSocket handshake reaps child and profile', 'handshake-error')
await regression('SIGINT during readiness reaps child and profile', 'readiness', { signal: 'SIGINT', at: 'chrome-ready' })
await regression('SIGTERM cancels pending CDP and reaps child and profile', 'pending', { signal: 'SIGTERM', at: 'cdp-pending' })
await regression('spawn error removes owned profile state', 'spawn-error')
await regression('unexpected DevTools state read error stops child', 'state-error')
await regression('unexpected child exit cancels pending CDP', 'child-exit')
await regression('closed CDP cancels pending command and stops child', 'cdp-close')
await regression('malformed CDP fails safely and stops owned child', 'malformed-cdp')
