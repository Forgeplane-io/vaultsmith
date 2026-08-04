import { useEffect, useMemo, useRef, useState } from 'react'
import {
  ApiError,
  fetchProfiles,
  maxInputBytes,
  OPERATION_TIMEOUT_MS,
  runOperation,
  type OperationMode,
  type Profile,
  utf8ByteLength,
} from './api'
import { formatAnsibleVaultSnippet, isValidAnsibleVariableIdentifier } from './ansibleSnippet'
import { inspectVaultFormat, type VaultFormatInspection } from './vaultFormat'
import './styles.css'

export default function App() {
  const [profiles, setProfiles] = useState<Profile[]>([])
  const [profileId, setProfileId] = useState('')
  const [destinationProfileId, setDestinationProfileId] = useState('')
  const [mode, setMode] = useState<OperationMode>('encrypt')
  const [value, setValue] = useState('')
  const [output, setOutput] = useState('')
  const [ansibleVariableName, setAnsibleVariableName] = useState('')
  const [ansibleSnippetFallback, setAnsibleSnippetFallback] = useState('')
  const [revealed, setRevealed] = useState(false)
  const [loadingProfiles, setLoadingProfiles] = useState(true)
  const [profileLoadFailed, setProfileLoadFailed] = useState(false)
  const [profileLoadAttempt, setProfileLoadAttempt] = useState(0)
  const [busy, setBusy] = useState(false)
  const [status, setStatus] = useState('Loading environments')
  const [error, setError] = useState('')
  const [modeNotice, setModeNotice] = useState('')
  const snippetCopyRequestRef = useRef(0)
  const resultCopyRequestRef = useRef(0)
  const operationControllerRef = useRef<AbortController | null>(null)
  const operationAbortReasonRef = useRef<'cancelled' | 'timeout' | null>(null)

  useEffect(() => {
    let active = true
    setLoadingProfiles(true)
    setProfileLoadFailed(false)
    setStatus('Loading environments…')
    const controller = new AbortController()
    fetchProfiles(controller.signal)
      .then((loadedProfiles) => {
        if (!active) return
        setProfiles(loadedProfiles)
        setProfileId((current) => current || loadedProfiles[0]?.id || '')
        setDestinationProfileId((current) => current || loadedProfiles[1]?.id || loadedProfiles[0]?.id || '')
        setError('')
        setStatus('')
      })
      .catch((reason: unknown) => {
        if (!active) return
        setProfileLoadFailed(true)
        setError(safeErrorMessage(reason, 'Profiles could not be loaded.', 'profiles'))
        setStatus('')
      })
      .finally(() => {
        if (active) setLoadingProfiles(false)
      })
    return () => {
      active = false
      controller.abort()
    }
  }, [profileLoadAttempt])

  useEffect(() => () => {
    operationControllerRef.current?.abort()
  }, [])

  const byteLength = useMemo(() => utf8ByteLength(value), [value])
  const byteLimit = maxInputBytes(mode)
  const overLimit = byteLength > byteLimit
  const visibleError = overLimit ? limitMessage(mode) : error
  const canSubmit = !loadingProfiles && !busy && profiles.length > 0 && profileId.length > 0 && (mode !== 'rotate' || destinationProfileId.length > 0) && value.length > 0 && !overLimit
  const canClear = !profileLoadFailed && Boolean(value || output || ansibleVariableName || error)
  const inputName = mode === 'encrypt' ? 'Value to protect' : mode === 'decrypt' ? 'Protected value to read' : 'Protected value to move'
  const outputName = mode === 'encrypt' ? 'Protected value' : mode === 'decrypt' ? 'Decrypted value' : 'Moved protected value'
  const modeGuidance = mode === 'encrypt'
    ? 'Choose an environment, then enter the value you want to protect.'
    : mode === 'decrypt'
      ? 'Choose an environment, then paste complete protected text. Do not paste a YAML file or an encrypt_string assignment.'
      : 'Choose where the value comes from and where it should go, then paste the protected text.'
  const shownOutput = mode === 'decrypt' && output && !revealed ? 'Decrypted value hidden' : output
  const copyDisabled = !output
  const copyLabel = mode === 'decrypt' && output && !revealed ? 'Copy without revealing' : 'Copy result'
  const canCopyAnsibleSnippet = Boolean(output) && (mode === 'encrypt' || mode === 'rotate') && isValidAnsibleVariableIdentifier(ansibleVariableName)
  const formatInspection = useMemo(
    () => mode === 'encrypt' ? null : inspectVaultFormat(value, profileId, byteLength),
    [byteLength, mode, profileId, value],
  )
  const selectedProfileLabel = profiles.find((profile) => profile.id === profileId)?.label || profileId
  const inputDescriptionIds = value && formatInspection
    ? 'input-byte-count vault-format-diagnostics'
    : 'input-byte-count'
  const heading = mode === 'encrypt'
    ? 'Protect a value.'
    : mode === 'decrypt'
      ? 'Read a protected value.'
      : 'Move a value safely.'
  const modeEyebrow = mode === 'encrypt' ? 'PROTECT' : mode === 'decrypt' ? 'READ' : 'MOVE'

  function invalidateOutput() {
    snippetCopyRequestRef.current += 1
    resultCopyRequestRef.current += 1
    setOutput('')
    setRevealed(false)
    setAnsibleSnippetFallback('')
    setError('')
    setStatus('')
  }

  function changeMode(nextMode: OperationMode) {
    const retainedInput = Boolean(value) && nextMode !== mode
    setMode(nextMode)
    invalidateOutput()
    setModeNotice(retainedInput
      ? nextMode === 'decrypt'
        ? 'Input kept; protected text expected.'
        : nextMode === 'rotate'
          ? 'Input kept; protected text expected.'
          : 'Input kept; plain value expected.'
      : '')
  }

  function changeValue(nextValue: string) {
    setValue(nextValue)
    invalidateOutput()
    setModeNotice('')
  }

  function changeProfile(nextProfileId: string) {
    setProfileId(nextProfileId)
    invalidateOutput()
  }

  function changeDestinationProfile(nextProfileId: string) {
    setDestinationProfileId(nextProfileId)
    invalidateOutput()
  }

  function useResultAsInput() {
    if (busy || !output) return

    const nextMode: OperationMode = mode === 'decrypt' ? 'encrypt' : 'decrypt'
    const result = output
    if (mode === 'rotate') setProfileId(destinationProfileId || profileId)
    setMode(nextMode)
    setValue(result)
    snippetCopyRequestRef.current += 1
    resultCopyRequestRef.current += 1
    setOutput('')
    setAnsibleVariableName('')
    setAnsibleSnippetFallback('')
    setRevealed(false)
    setError('')
    setModeNotice('')
    setStatus(nextMode === 'decrypt'
      ? 'Switched to decrypt mode and moved the result into the protected value input.'
      : 'Switched to encrypt mode and moved the result into the value input.')
  }

  function resultCopyFallbackMessage(prefix: string): string {
    const nextStep = mode === 'decrypt' && !revealed
      ? 'reveal the result to copy it manually'
      : 'copy the result manually'
    return `${prefix}; ${nextStep}`
  }

  function retryProfiles() {
    if (busy) return
    setProfiles([])
    setProfileId('')
    setDestinationProfileId('')
    setLoadingProfiles(true)
    setProfileLoadFailed(false)
    setError('')
    setStatus('Loading environments…')
    setProfileLoadAttempt((attempt) => attempt + 1)
  }

  async function submit() {
    if (!value) {
      setError('Enter a value first')
      return
    }
    if (overLimit) {
      setError(limitMessage(mode))
      return
    }

    const operationMode = mode
    const controller = new AbortController()
    operationControllerRef.current = controller
    operationAbortReasonRef.current = null
    const timeoutId = window.setTimeout(() => {
      operationAbortReasonRef.current = 'timeout'
      controller.abort()
    }, OPERATION_TIMEOUT_MS)

    setBusy(true)
    snippetCopyRequestRef.current += 1
    resultCopyRequestRef.current += 1
    setError('')
    setOutput('')
    setAnsibleSnippetFallback('')
    setRevealed(false)
    setModeNotice('')
    setStatus(operationMode === 'encrypt' ? 'Encrypting…' : operationMode === 'decrypt' ? 'Decrypting…' : 'Rotating…')

    try {
      const request = operationMode === 'rotate'
        ? { mode: operationMode, sourceProfileId: profileId, destinationProfileId, value }
        : { profileId, mode: operationMode, value }
      const result = await runOperation(request, controller.signal)
      setOutput(result)
      setStatus(operationMode === 'encrypt' ? 'Protected value ready' : operationMode === 'decrypt' ? 'Decrypted value ready' : 'Moved value ready')
    } catch (reason: unknown) {
      if (controller.signal.aborted) {
        if (operationAbortReasonRef.current === 'timeout') {
          setError('The operation timed out. Check the service and try again.')
          setStatus('Operation timed out')
        } else {
          setStatus('Operation cancelled')
        }
      } else {
        setError(operationErrorMessage(reason, operationMode))
        setStatus('')
      }
    } finally {
      window.clearTimeout(timeoutId)
      if (operationControllerRef.current === controller) {
        operationControllerRef.current = null
        operationAbortReasonRef.current = null
      }
      setBusy(false)
    }
  }

  function cancelOperation() {
    if (!busy || !operationControllerRef.current) return
    operationAbortReasonRef.current = 'cancelled'
    operationControllerRef.current.abort()
  }

  async function copyResult() {
    if (!output) return
    const requestId = ++resultCopyRequestRef.current
    if (!navigator.clipboard?.writeText) {
      if (resultCopyRequestRef.current !== requestId) return
      setError(resultCopyFallbackMessage('Clipboard access is unavailable'))
      return
    }
    try {
      await navigator.clipboard.writeText(output)
      if (resultCopyRequestRef.current !== requestId) return
      setStatus(mode === 'decrypt' && !revealed ? 'Copied without revealing the value' : 'Copied')
    } catch {
      if (resultCopyRequestRef.current !== requestId) return
      setError(resultCopyFallbackMessage('Clipboard access was blocked'))
    }
  }

  async function copyAnsibleSnippet() {
    if (!output || (mode !== 'encrypt' && mode !== 'rotate') || !isValidAnsibleVariableIdentifier(ansibleVariableName)) return

    const requestId = ++snippetCopyRequestRef.current
    let snippet: string
    try {
      snippet = formatAnsibleVaultSnippet(ansibleVariableName, output)
    } catch {
      if (snippetCopyRequestRef.current !== requestId) return
      setAnsibleSnippetFallback('')
      setStatus('')
      setError('Could not prepare the Ansible snippet; copy the result manually')
      return
    }
    if (!navigator.clipboard?.writeText) {
      if (snippetCopyRequestRef.current !== requestId) return
      setAnsibleSnippetFallback(snippet)
      setStatus('')
      setError('Clipboard access is unavailable; copy the Ansible snippet manually')
      return
    }
    try {
      await navigator.clipboard.writeText(snippet)
      if (snippetCopyRequestRef.current !== requestId) return
      setAnsibleSnippetFallback('')
      setError('')
      setStatus('Copied Ansible snippet')
    } catch {
      if (snippetCopyRequestRef.current !== requestId) return
      setAnsibleSnippetFallback(snippet)
      setStatus('')
      setError('Clipboard access was blocked; copy the Ansible snippet manually')
    }
  }

  function clearAll() {
    if (busy || !canClear) return
    snippetCopyRequestRef.current += 1
    resultCopyRequestRef.current += 1
    setValue('')
    setOutput('')
    setAnsibleVariableName('')
    setAnsibleSnippetFallback('')
    setRevealed(false)
    setError('')
    setStatus('')
    setModeNotice('')
  }

  return (
    <div className="console-app" data-mode={mode}>
      <header className="console-topbar">
        <div className="topbar-inner">
          <div className="brand-lockup">
            <span className="brand-mark" aria-hidden="true">V</span>
            <div>
              <div className="brand-name">Vaultsmith</div>
              <div className="brand-subtitle">Value protection</div>
            </div>
          </div>
          <div className="topbar-context">
            <strong>Protect · read · move</strong>
          </div>
        </div>
      </header>

      <main className="console-content">
        <div className="content-heading">
          <div className="heading-copy">
            <div className="heading-eyebrow"><span className="heading-eyebrow-dot" aria-hidden="true" />{modeEyebrow}</div>
            <h1>{heading}</h1>
            <p>{modeGuidance}</p>
          </div>
        </div>

        <section className="workbench-card" aria-labelledby="workbench-title">
          <div className="workbench-header">
            <div>
              <div className="workbench-kicker">01 / Start</div>
              <h2 id="workbench-title">Choose an action</h2>
            </div>
            {status && <p className="status-line" role="status" aria-live="polite">{status}</p>}
          </div>

          {visibleError && (
            <div className="error-banner" role="alert">
              <span>{visibleError}</span>
              {profileLoadFailed && !loadingProfiles && <button className="secondary-button" type="button" onClick={retryProfiles}>Retry loading environments</button>}
            </div>
          )}

          <form
            className="operation-form"
            aria-busy={busy}
            onSubmit={(event) => {
              event.preventDefault()
              void submit()
            }}
          >
            <div className="control-strip">
              {mode === 'rotate' ? (
                <div className="rotate-profile-fields">
                  <div className="field-label">
                    <span className="field-kicker">From</span>
                    <label htmlFor="source-profile-select">From environment</label>
                    <select
                      id="source-profile-select"
                      value={profileId}
                      disabled={loadingProfiles || busy || profiles.length === 0}
                      onChange={(event) => changeProfile(event.target.value)}
                      aria-describedby="source-profile-help"
                    >
                      {profiles.map((profile) => (
                        <option key={profile.id} value={profile.id}>{profile.label}</option>
                      ))}
                    </select>
                    <span className="field-help" id="source-profile-help">Where it comes from.</span>
                  </div>
                  <div className="field-label">
                    <span className="field-kicker">To</span>
                    <label htmlFor="destination-profile-select">To environment</label>
                    <select
                      id="destination-profile-select"
                      value={destinationProfileId}
                      disabled={loadingProfiles || busy || profiles.length === 0}
                      onChange={(event) => changeDestinationProfile(event.target.value)}
                      aria-describedby="destination-profile-help"
                    >
                      {profiles.map((profile) => (
                        <option key={profile.id} value={profile.id}>{profile.label}</option>
                      ))}
                    </select>
                    <span className="field-help" id="destination-profile-help">Where it should go.</span>
                  </div>
                </div>
              ) : (
                <div className="field-label">
                  <span className="field-kicker">Use in</span>
                  <label htmlFor="profile-select">Environment</label>
                  <select
                    id="profile-select"
                    value={profileId}
                    disabled={loadingProfiles || busy || profiles.length === 0}
                    onChange={(event) => changeProfile(event.target.value)}
                    aria-describedby="profile-help"
                  >
                    {profiles.length === 0 && <option value="">No profiles available</option>}
                    {profiles.map((profile) => (
                      <option key={profile.id} value={profile.id}>{profile.label}</option>
                    ))}
                  </select>
                  <span className="field-help" id="profile-help">Where this value will be used.</span>
                </div>
              )}

              <fieldset className="mode-fieldset">
                <legend><span className="field-kicker">Action</span><span>What do you want to do?</span></legend>
                <div className="mode-switch" role="group" aria-label="Operation mode">
                  <button type="button" className={mode === 'encrypt' ? 'mode-button active' : 'mode-button'} aria-label="Set encrypt mode" aria-pressed={mode === 'encrypt'} onClick={() => changeMode('encrypt')} disabled={busy}>Encrypt</button>
                  <button type="button" className={mode === 'decrypt' ? 'mode-button active' : 'mode-button'} aria-label="Set decrypt mode" aria-pressed={mode === 'decrypt'} onClick={() => changeMode('decrypt')} disabled={busy}>Decrypt</button>
                  <button type="button" className={mode === 'rotate' ? 'mode-button active' : 'mode-button'} aria-label="Set rotate mode" aria-pressed={mode === 'rotate'} onClick={() => changeMode('rotate')} disabled={busy}>Rotate</button>
                </div>
              </fieldset>
            </div>

            {modeNotice && <p className="mode-notice" aria-live="polite">{modeNotice}</p>}

            <div className="editor-grid">
              <div className="editor-card">
                <div className="editor-card-header">
                  <div className="editor-heading-group">
                    <span className="editor-index" aria-hidden="true">01</span>
                    <div><label className="editor-caption" htmlFor="value-input">{inputName}</label><span className="editor-subtitle">Enter here</span></div>
                  </div>
                  <span className="editor-limit">{formatLimit(byteLimit)} max</span>
                </div>
                <textarea
                  id="value-input"
                  value={value}
                  onChange={(event) => changeValue(event.target.value)}
                  placeholder={mode === 'encrypt' ? 'Paste a value…' : 'Paste protected text…'}
                  disabled={loadingProfiles || busy || profiles.length === 0}
                  spellCheck={false}
                  autoComplete="off"
                  autoCorrect="off"
                  autoCapitalize="off"
                  aria-describedby={inputDescriptionIds}
                  rows={12}
                />
                <div className="editor-card-footer" id="input-byte-count"><span>{mode === 'encrypt' ? 'Value' : 'Protected text'}</span><strong>{byteLength.toLocaleString()} / {byteLimit.toLocaleString()} bytes</strong></div>
                {formatInspection && value && <VaultFormatDiagnostics inspection={formatInspection} selectedProfileId={profileId} selectedProfileLabel={selectedProfileLabel} />}
                <div className="panel-actions">
                  <button className="primary-button" type="submit" disabled={!canSubmit}>
                    {busy ? (mode === 'encrypt' ? 'Encrypting…' : mode === 'decrypt' ? 'Decrypting…' : 'Rotating…') : (mode === 'encrypt' ? 'Encrypt' : mode === 'decrypt' ? 'Decrypt' : 'Rotate')}
                  </button>
                  {busy && <button className="secondary-button" type="button" onClick={cancelOperation}>Cancel</button>}
                  <button className="quiet-button" type="button" onClick={clearAll} disabled={busy || !canClear}>Clear values</button>
                </div>
              </div>

              <div className="editor-card output-card">
                <div className="editor-card-header">
                  <div className="editor-heading-group">
                    <span className="editor-index" aria-hidden="true">02</span>
                    <div><label className="editor-caption" htmlFor="result-output">{outputName}</label><span className="editor-subtitle">Copy when ready</span></div>
                  </div>
                  <span className="editor-limit">Output</span>
                </div>
                <textarea
                  id="result-output"
                  value={shownOutput}
                  readOnly
                  spellCheck={false}
                  autoComplete="off"
                  autoCorrect="off"
                  autoCapitalize="off"
                  rows={12}
                  className={mode === 'decrypt' && output && !revealed ? 'masked-output' : ''}
                  placeholder="Result appears here."
                />
                {output && (mode === 'encrypt' || mode === 'rotate') && (
                  <div className="snippet-controls">
                    <div className="field-label">
                      <span className="field-kicker">Ansible</span>
                      <label htmlFor="ansible-variable-name">Ansible variable name</label>
                      <input
                        id="ansible-variable-name"
                        value={ansibleVariableName}
                        onChange={(event) => {
                          snippetCopyRequestRef.current += 1
                          setAnsibleVariableName(event.target.value)
                          setAnsibleSnippetFallback('')
                          setStatus('')
                          if (error) setError('')
                        }}
                        onKeyDown={(event) => {
                          if (event.key === 'Enter') event.preventDefault()
                        }}
                        placeholder="app_secret"
                        autoComplete="off"
                        spellCheck={false}
                        autoCorrect="off"
                        autoCapitalize="off"
                        aria-describedby="ansible-variable-name-help"
                        aria-invalid={ansibleVariableName.length > 0 && !isValidAnsibleVariableIdentifier(ansibleVariableName)}
                      />
                      <span className="field-help" id="ansible-variable-name-help">Letters, numbers, and underscores; start with a letter or underscore. Reserved Ansible names are not allowed.</span>
                    </div>
                    <button className="secondary-button" type="button" onClick={() => void copyAnsibleSnippet()} disabled={!canCopyAnsibleSnippet}>Copy Ansible snippet</button>
                  </div>
                )}
                {ansibleSnippetFallback && (
                  <div className="snippet-fallback">
                    <label htmlFor="ansible-snippet-fallback">Ansible snippet to copy manually</label>
                    <textarea
                      id="ansible-snippet-fallback"
                      value={ansibleSnippetFallback}
                      readOnly
                      spellCheck={false}
                      aria-describedby="ansible-snippet-fallback-help"
                      rows={8}
                    />
                    <span className="field-help" id="ansible-snippet-fallback-help">Clipboard access failed. Select this formatted snippet and copy it manually.</span>
                  </div>
                )}
                <div className="panel-actions output-actions">
                  {mode === 'decrypt' && output && <button className="secondary-button" type="button" onClick={() => { setRevealed((current) => !current); setError('') }}>{revealed ? 'Hide result' : 'Reveal result'}</button>}
                  <button className="secondary-button" type="button" onClick={useResultAsInput} disabled={busy || !output}>Use result as input</button>
                  <button className="secondary-button" type="button" onClick={() => void copyResult()} disabled={copyDisabled}>{copyLabel}</button>
                </div>
              </div>
            </div>
          </form>
        </section>
      </main>
    </div>
  )
}

function VaultFormatDiagnostics({ inspection, selectedProfileId, selectedProfileLabel }: { inspection: VaultFormatInspection; selectedProfileId: string; selectedProfileLabel: string }) {
  const state = inspection.status === 'recognized' && inspection.issues.length === 0 ? 'recognized' : 'warning'
  const guidance = formatGuidance(inspection, selectedProfileId, selectedProfileLabel)

  return (
    <section className="format-inspector" id="vault-format-diagnostics" data-state={state} aria-label="Vault format diagnostics">
      <div className="format-inspector-heading">
        <div className="format-inspector-title">
          <span className="inspector-mark" aria-hidden="true">↳</span>
          <div><span>Header inspection</span><strong>{formatName(inspection)}</strong></div>
        </div>
        <span className="inspector-state">{state === 'recognized' ? 'Parsed' : 'Review'}</span>
      </div>
      <p className="format-inspector-note">Header-only advisory; not cryptographic validation.</p>
      <dl className="format-inspector-grid">
        <div><dt>Cipher</dt><dd>{cipherName(inspection)}</dd></div>
        <div><dt>Vault ID label</dt><dd>{inspection.label || 'None'}</dd></div>
        <div><dt>Input size</dt><dd>{inspection.byteLength.toLocaleString()} / {inspection.byteLimit.toLocaleString()} bytes</dd></div>
      </dl>
      <p className="format-inspector-guidance" aria-live="polite">{guidance}</p>
    </section>
  )
}

function formatName(inspection: VaultFormatInspection): string {
  if (inspection.status === 'recognized' && inspection.version) return `Vault ${inspection.version}`
  if (inspection.status === 'unsupported') return 'Unrecognized format'
  return 'Malformed header'
}

function cipherName(inspection: VaultFormatInspection): string {
  if (inspection.cipher === 'AES256') return 'AES256'
  if (inspection.cipher === 'unrecognized') return 'Unrecognized'
  return '—'
}

function formatGuidance(inspection: VaultFormatInspection, selectedProfileId: string, selectedProfileLabel: string): string {
  if (inspection.issues.includes('over-limit')) return 'Vault text exceeds the 5 MiB input limit.'
  if (inspection.issues.includes('missing-header')) return 'No Ansible Vault header was found. Paste complete Vault text.'
  if (inspection.issues.includes('malformed-header')) return 'The Vault header is malformed. Paste complete Ansible Vault text.'
  if (inspection.issues.includes('unsupported-version') || inspection.issues.includes('unsupported-cipher')) {
    return 'The Vault version or cipher is not recognized by this inspector. The backend remains authoritative.'
  }
  if (inspection.issues.includes('label-too-long')) return 'The Vault ID label is too long for advisory display; the backend remains authoritative.'
  if (inspection.issues.includes('label-unavailable')) return 'The Vault ID label is omitted from advisory display because it contains unsupported control characters; the backend remains authoritative.'
  if (inspection.issues.includes('label-mismatch')) {
    const environmentDescription = selectedProfileLabel && selectedProfileLabel !== selectedProfileId
      ? `ID “${selectedProfileId || 'current'}” (${selectedProfileLabel})`
      : `ID “${selectedProfileId || 'current'}”`
    return `Vault ID label “${inspection.label}” differs from selected environment ${environmentDescription}. This is advisory; the backend remains authoritative.`
  }
  return ''
}

function safeErrorMessage(reason: unknown, fallback: string, context: 'profiles' | 'operation' = 'operation'): string {
  if (!(reason instanceof ApiError)) return fallback
  if (reason.code === 'network_error') return 'Unable to reach the Vaultsmith service'
  if (reason.code === 'profiles_timeout') return 'Environment loading timed out. Check the service and try again.'
  if (reason.code === 'invalid_response') return 'The service returned an invalid response'
  if (reason.code === 'not_ready') return 'Vaultsmith service is not ready. Try again shortly.'
  if (reason.code === 'not_found') {
    return context === 'profiles'
      ? 'The environments endpoint was not found. Check the service route and try again.'
      : 'The selected environment was not found. Reload environments and try again.'
  }
  if (reason.code === 'invalid_request') return 'The request was not accepted. Check the selected environments and input.'
  if (reason.code === 'method_not_allowed') return 'The requested operation is not available.'
  return fallback
}

function operationErrorMessage(reason: unknown, mode: OperationMode): string {
  if (reason instanceof ApiError && reason.code === 'operation_failed') {
    if (mode === 'decrypt') {
      return 'Could not read this value. Check the selected environment and paste complete protected text.'
    }
    if (mode === 'rotate') {
      return 'Could not move this value. Check both selected environments and paste complete protected text.'
    }
    return 'Could not protect this value. Check the selected environment and try again.'
  }
  return safeErrorMessage(reason, 'Value operation failed')
}

function formatLimit(bytes: number): string {
  return bytes === 1 << 20 ? '1 MiB' : '5 MiB'
}

function limitMessage(mode: OperationMode): string {
  return mode === 'encrypt' ? 'Value exceeds the 1 MiB limit' : 'Vault text exceeds the 5 MiB limit'
}
