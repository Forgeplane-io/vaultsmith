import { useEffect, useMemo, useRef, useState, type ClipboardEvent } from 'react'
import {
  ApiError,
  fetchProfiles,
  fetchSession,
  logout,
  maxInputBytes,
  OPERATION_TIMEOUT_MS,
  runOperation,
  type OperationMode,
  type Profile,
  type Session,
  utf8ByteLength,
} from './api'
import {
  ansibleVariableValidationMessage,
  formatAnsibleVaultSnippet,
  isValidAnsibleVariableIdentifier,
} from './ansibleSnippet'
import { normalizeVaultPaste } from './pasteHandling'
import { inspectVaultFormat, type VaultFormatInspection } from './vaultFormat'
import './styles.css'

type CopyFeedback = {
  tone: 'success' | 'error'
  message: string
}

export default function App() {
  const [profiles, setProfiles] = useState<Profile[]>([])
  const [session, setSession] = useState<Session | null>(null)
  const [signedOut, setSignedOut] = useState(false)
  const [signingOut, setSigningOut] = useState(false)
  const [logoutFailed, setLogoutFailed] = useState(false)
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
  const [profileLoadError, setProfileLoadError] = useState('')
  const [loadFailureStage, setLoadFailureStage] = useState<'session' | 'profiles' | null>(null)
  const [profileSnapshotValid, setProfileSnapshotValid] = useState(false)
  const [recoveringStaleCapabilities, setRecoveringStaleCapabilities] = useState(false)
  const [profileLoadAttempt, setProfileLoadAttempt] = useState(0)
  const [busy, setBusy] = useState(false)
  const [status, setStatus] = useState('Checking session…')
  const [error, setError] = useState('')
  const [resultCopyFeedback, setResultCopyFeedback] = useState<CopyFeedback | null>(null)
  const [snippetCopyFeedback, setSnippetCopyFeedback] = useState<CopyFeedback | null>(null)
  const [modeNotice, setModeNotice] = useState('')
  const snippetCopyRequestRef = useRef(0)
  const resultCopyRequestRef = useRef(0)
  const operationControllerRef = useRef<AbortController | null>(null)
  const operationAbortReasonRef = useRef<'cancelled' | 'timeout' | null>(null)
  const operationGenerationRef = useRef(0)
  const profileLoadControllerRef = useRef<AbortController | null>(null)
  const profileRefreshControllerRef = useRef<AbortController | null>(null)
  const logoutControllerRef = useRef<AbortController | null>(null)
  const signingOutRef = useRef(false)
  const initialProfileSelectionRef = useRef(true)
  const modeRef = useRef(mode)
  const valueRef = useRef(value)
  modeRef.current = mode
  valueRef.current = value

  function applyLoadedProfiles(loadedProfiles: Profile[], announceModeChange = false) {
    const previousMode = modeRef.current
    const nextMode = modeIsAvailable(loadedProfiles, previousMode)
      ? previousMode
      : preferredAvailableMode(loadedProfiles)
    const eligibleProfiles = profilesForMode(loadedProfiles, nextMode)
    const encryptProfiles = profilesForMode(loadedProfiles, 'encrypt')
    const allowInitialSelection = initialProfileSelectionRef.current && valueRef.current.length === 0
    initialProfileSelectionRef.current = false
    setProfiles(loadedProfiles)
    if (nextMode !== previousMode) {
      setMode(nextMode)
      if (announceModeChange) {
        setModeNotice(`${operationLabel(previousMode)} is unavailable. Switched to ${operationLabel(nextMode)}.`)
      }
    }
    setProfileId((current) => profileIsEligible(eligibleProfiles, current)
      ? current
      : allowInitialSelection ? eligibleProfiles[0]?.id || '' : '')
    setDestinationProfileId((current) => profileIsEligible(encryptProfiles, current)
      ? current
      : allowInitialSelection ? encryptProfiles[1]?.id || encryptProfiles[0]?.id || '' : '')
  }

  useEffect(() => {
    if (signingOutRef.current) return
    let active = true
    let loadStage: 'session' | 'profiles' = 'session'
    const recoveringStaleSnapshot = recoveringStaleCapabilities
    setProfileSnapshotValid(false)
    setLoadingProfiles(true)
    setProfileLoadFailed(false)
    setProfileLoadError('')
    setLoadFailureStage(null)
    setModeNotice('')
    setStatus(recoveringStaleSnapshot ? 'Refreshing environments…' : 'Checking session…')
    const controller = new AbortController()
    profileLoadControllerRef.current = controller
    const hasAuthority = () => active
      && profileLoadControllerRef.current === controller
      && !controller.signal.aborted
      && !signingOutRef.current
    fetchSession(controller.signal)
      .then((session) => {
        if (!hasAuthority()) return undefined
        setSession(session)
        if (session.authRequired && !session.authenticated) {
          redirectToLogin()
          setStatus('Sign-in required…')
          return undefined
        }
        loadStage = 'profiles'
        setStatus(recoveringStaleSnapshot ? 'Refreshing environments…' : 'Loading environments…')
        return fetchProfiles(controller.signal)
      })
      .then((loadedProfiles) => {
        if (!hasAuthority() || !loadedProfiles) return
        applyLoadedProfiles(loadedProfiles, recoveringStaleSnapshot)
        setProfileSnapshotValid(true)
        setRecoveringStaleCapabilities(false)
        setError('')
        setProfileLoadError('')
        setLoadFailureStage(null)
        setStatus(recoveringStaleSnapshot
          ? 'Your permissions changed. Environments were refreshed; review the selection and try again.'
          : '')
      })
      .catch((reason: unknown) => {
        if (!hasAuthority()) return
        if (reason instanceof ApiError && reason.code === 'unauthorized') {
          redirectToLogin()
          setStatus('Sign-in required…')
          return
        }
        setProfileLoadFailed(true)
        setLoadFailureStage(loadStage)
        setProfileLoadError(loadStage === 'session'
          ? safeErrorMessage(reason, 'Session could not be loaded.', 'session')
          : recoveringStaleSnapshot
            ? 'Your permissions changed, but environments could not be refreshed. Check the service and retry loading environments.'
            : safeErrorMessage(reason, 'Profiles could not be loaded.', 'profiles'))
        setStatus('')
      })
      .finally(() => {
        if (!hasAuthority()) return
        profileLoadControllerRef.current = null
        setLoadingProfiles(false)
      })
    return () => {
      active = false
      if (profileLoadControllerRef.current === controller) profileLoadControllerRef.current = null
      controller.abort()
    }
  }, [profileLoadAttempt])

  useEffect(() => () => {
    operationGenerationRef.current += 1
    operationControllerRef.current?.abort()
    const profileLoadController = profileLoadControllerRef.current
    profileLoadControllerRef.current = null
    profileLoadController?.abort()
    const profileRefreshController = profileRefreshControllerRef.current
    profileRefreshControllerRef.current = null
    profileRefreshController?.abort()
    logoutControllerRef.current?.abort()
    logoutControllerRef.current = null
  }, [])

  const byteLength = useMemo(() => utf8ByteLength(value), [value])
  const byteLimit = maxInputBytes(mode)
  const overLimit = byteLength > byteLimit
  const visibleError = overLimit ? limitMessage(mode) : error || profileLoadError
  const encryptProfiles = useMemo(() => profilesForMode(profiles, 'encrypt'), [profiles])
  const decryptProfiles = useMemo(() => profilesForMode(profiles, 'decrypt'), [profiles])
  const eligibleProfiles = mode === 'encrypt' ? encryptProfiles : decryptProfiles
  const profileSnapshotReady = profileSnapshotValid && !loadingProfiles && !profileLoadFailed
  const encryptAvailable = encryptProfiles.length > 0
  const decryptAvailable = decryptProfiles.length > 0
  const rotateAvailable = encryptAvailable && decryptAvailable
  const modeAvailable = mode === 'encrypt' ? encryptAvailable : mode === 'decrypt' ? decryptAvailable : rotateAvailable
  const selectedProfileEligible = profileIsEligible(eligibleProfiles, profileId)
  const selectedDestinationEligible = mode !== 'rotate' || profileIsEligible(encryptProfiles, destinationProfileId)
  const workbenchLocked = busy || signingOut
  const canSubmit = profileSnapshotReady && !workbenchLocked && modeAvailable && selectedProfileEligible && selectedDestinationEligible && value.length > 0 && !overLimit
  const canClear = Boolean(value || output || ansibleVariableName)
  const inputName = mode === 'encrypt' ? 'Value to encrypt' : mode === 'decrypt' ? 'Protected value to decrypt' : 'Protected value to re-key'
  const outputName = mode === 'encrypt' ? 'Encrypted value' : mode === 'decrypt' ? 'Decrypted value' : 'Re-keyed value'
  const modeGuidance = mode === 'encrypt'
    ? 'Choose an environment, then enter a value to encrypt.'
    : mode === 'decrypt'
      ? 'Choose an environment, then paste protected text or a YAML !vault block to decrypt.'
      : 'Choose source and destination environments, then paste protected text or a YAML !vault block to re-key.'
  const shownOutput = mode === 'decrypt' && output && !revealed ? 'Decrypted value hidden' : output
  const outputByteLength = useMemo(() => utf8ByteLength(output), [output])
  const copyDisabled = workbenchLocked || !output
  const copyLabel = mode === 'decrypt' && output && !revealed ? 'Copy without revealing' : 'Copy result'
  const canCopyAnsibleSnippet = !workbenchLocked && Boolean(output) && (mode === 'encrypt' || mode === 'rotate') && isValidAnsibleVariableIdentifier(ansibleVariableName)
  const ansibleVariableValidation = ansibleVariableValidationMessage(ansibleVariableName)
  const handoffTargetProfileId = mode === 'rotate' ? destinationProfileId : profileId
  const handoffTargetMode: OperationMode = mode === 'decrypt' ? 'encrypt' : 'decrypt'
  const handoffEligible = profileSnapshotReady && profileIsEligible(profilesForMode(profiles, handoffTargetMode), handoffTargetProfileId)
  const canUseResultAsInput = !workbenchLocked && Boolean(output) && handoffEligible
  const handoffLabel = mode === 'encrypt'
    ? 'Decrypt this result'
    : mode === 'decrypt'
      ? 'Encrypt this result'
      : 'Decrypt with destination environment'
  const handoffUnavailableReason = mode === 'rotate'
    ? 'The destination environment is not available for decryption.'
    : handoffTargetMode === 'decrypt'
      ? 'The selected environment is not available for decryption.'
      : 'The selected environment is not available for encryption.'
  const formatInspection = useMemo(
    () => mode === 'encrypt' ? null : inspectVaultFormat(value, profileId, byteLength),
    [byteLength, mode, profileId, value],
  )
  const suggestedDecryptProfile = useMemo(
    () => profileSnapshotReady && mode !== 'encrypt' && formatInspection
      ? vaultIdSuggestedProfile(formatInspection, profileId, decryptProfiles)
      : null,
    [decryptProfiles, formatInspection, mode, profileId, profileSnapshotReady],
  )
  const selectedProfileLabel = profiles.find((profile) => profile.id === profileId)?.label || profileId
  const inputDescriptionIds = value && formatInspection
    ? 'input-byte-count vault-format-diagnostics'
    : 'input-byte-count'
  const heading = mode === 'encrypt'
    ? 'Encrypt a value'
    : mode === 'decrypt'
      ? 'Decrypt a protected value'
      : 'Re-key a protected value'

  function invalidateOutput() {
    snippetCopyRequestRef.current += 1
    resultCopyRequestRef.current += 1
    setOutput('')
    setRevealed(false)
    setAnsibleSnippetFallback('')
    setResultCopyFeedback(null)
    setSnippetCopyFeedback(null)
    setError('')
    if (!recoveringStaleCapabilities) setStatus('')
  }

  function changeMode(nextMode: OperationMode) {
    if (signingOut) return
    const retainedInput = Boolean(value) && nextMode !== mode
    const nextProfiles = profilesForMode(profiles, nextMode)
    setProfileId((current) => profileIsEligible(nextProfiles, current) ? current : '')
    setDestinationProfileId((current) => profileIsEligible(encryptProfiles, current) ? current : '')
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
    if (signingOut) return
    setValue(nextValue)
    invalidateOutput()
    setModeNotice('')
  }

  function handlePaste(event: ClipboardEvent<HTMLTextAreaElement>) {
    if (signingOut || mode === 'encrypt') return

    const pastedText = event.clipboardData.getData('text/plain')
    const normalized = normalizeVaultPaste(pastedText)
    if (!normalized || normalized === pastedText) return

    event.preventDefault()
    changeValue(normalized)
    setModeNotice('Protected text normalized for Vault operation.')
  }

  function changeProfile(nextProfileId: string) {
    if (signingOut) return
    setProfileId(nextProfileId)
    invalidateOutput()
  }

  function useSuggestedDecryptProfile(expectedProfileId: string) {
    if (workbenchLocked || mode === 'encrypt' || !profileSnapshotReady) return

    const currentInspection = inspectVaultFormat(value, profileId)
    const currentSuggestion = vaultIdSuggestedProfile(currentInspection, profileId, decryptProfiles)
    if (currentSuggestion?.id !== expectedProfileId) return

    changeProfile(currentSuggestion.id)
  }

  function changeDestinationProfile(nextProfileId: string) {
    if (signingOut) return
    setDestinationProfileId(nextProfileId)
    invalidateOutput()
  }

  function useResultAsInput() {
    if (workbenchLocked || !canUseResultAsInput) return

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
    setResultCopyFeedback(null)
    setSnippetCopyFeedback(null)
    setRevealed(false)
    setError('')
    setModeNotice('')
    setStatus(nextMode === 'decrypt'
      ? 'Switched to Decrypt mode and placed the result in the protected value input.'
      : 'Switched to Encrypt mode and placed the result in the value input.')
  }

  function resultCopyFallbackMessage(prefix: string): string {
    const nextStep = mode === 'decrypt' && !revealed
      ? 'reveal the result to copy it manually'
      : 'copy the result manually'
    return `${prefix}; ${nextStep}`
  }

  async function refreshCapabilitiesAfterForbidden() {
    profileRefreshControllerRef.current?.abort()
    const controller = new AbortController()
    profileRefreshControllerRef.current = controller
    setRecoveringStaleCapabilities(true)
    setProfileSnapshotValid(false)
    setLoadingProfiles(true)
    setProfileLoadFailed(false)
    setProfileLoadError('')
    setLoadFailureStage(null)
    setModeNotice('')
    setError('')
    setStatus('Refreshing environments…')

    try {
      const loadedProfiles = await fetchProfiles(controller.signal)
      if (profileRefreshControllerRef.current !== controller || controller.signal.aborted) return
      applyLoadedProfiles(loadedProfiles, true)
      setProfileSnapshotValid(true)
      setRecoveringStaleCapabilities(false)
      setStatus('Your permissions changed. Environments were refreshed; review the selection and try again.')
    } catch (reason: unknown) {
      if (profileRefreshControllerRef.current !== controller || controller.signal.aborted) return
      if (reason instanceof ApiError && reason.code === 'unauthorized') {
        setRecoveringStaleCapabilities(false)
        redirectToLogin()
        setStatus('Sign-in required…')
        return
      }
      setProfileLoadFailed(true)
      setLoadFailureStage('profiles')
      setProfileLoadError('Your permissions changed, but environments could not be refreshed. Check the service and retry loading environments.')
      setStatus('')
    } finally {
      if (profileRefreshControllerRef.current === controller) {
        profileRefreshControllerRef.current = null
        setLoadingProfiles(false)
      }
    }
  }

  function retryProfiles() {
    if (workbenchLocked || signingOutRef.current) return
    const retryingSession = loadFailureStage === 'session'
    setProfileSnapshotValid(false)
    setLoadingProfiles(true)
    setProfileLoadFailed(false)
    setProfileLoadError('')
    setLoadFailureStage(null)
    setError('')
    setStatus(recoveringStaleCapabilities
      ? 'Refreshing environments…'
      : retryingSession ? 'Checking session…' : 'Loading environments…')
    setProfileLoadAttempt((attempt) => attempt + 1)
  }

  async function submit() {
    if (signingOut) return
    if (!profileSnapshotReady || !selectedProfileEligible || !selectedDestinationEligible) {
      setError(mode === 'rotate'
        ? 'Select an available source and destination environment.'
        : 'Select an available environment.')
      return
    }
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
    const operationGeneration = operationGenerationRef.current + 1
    operationGenerationRef.current = operationGeneration
    operationControllerRef.current = controller
    operationAbortReasonRef.current = null
    const timeoutId = window.setTimeout(() => {
      operationAbortReasonRef.current = 'timeout'
      controller.abort()
    }, OPERATION_TIMEOUT_MS)
    const isCurrentOperation = () => operationGenerationRef.current === operationGeneration && operationControllerRef.current === controller

    setBusy(true)
    snippetCopyRequestRef.current += 1
    resultCopyRequestRef.current += 1
    setError('')
    setOutput('')
    setAnsibleSnippetFallback('')
    setResultCopyFeedback(null)
    setSnippetCopyFeedback(null)
    setRevealed(false)
    setModeNotice('')
    setStatus(operationProgressLabel(operationMode))

    try {
      const request = operationMode === 'rotate'
        ? { mode: operationMode, sourceProfileId: profileId, destinationProfileId, value }
        : { profileId, mode: operationMode, value }
      const result = await runOperation(request, controller.signal)
      if (!isCurrentOperation()) return
      if (controller.signal.aborted) {
        if (operationAbortReasonRef.current === 'timeout') {
          setError('The operation timed out. Check the service and try again.')
          setStatus('Operation timed out')
        } else {
          setStatus('Operation cancelled')
        }
        return
      }
      setOutput(result)
      setStatus(operationReadyLabel(operationMode))
    } catch (reason: unknown) {
      if (!isCurrentOperation()) return
      if (controller.signal.aborted) {
        if (operationAbortReasonRef.current === 'timeout') {
          setError('The operation timed out. Check the service and try again.')
          setStatus('Operation timed out')
        } else {
          setStatus('Operation cancelled')
        }
      } else {
        if (reason instanceof ApiError && reason.code === 'unauthorized') {
          redirectToLogin()
          setStatus('Sign-in required…')
          return
        }
        if (reason instanceof ApiError && reason.status === 403 && reason.code === 'forbidden') {
          window.clearTimeout(timeoutId)
          operationControllerRef.current = null
          operationAbortReasonRef.current = null
          setBusy(false)
          await refreshCapabilitiesAfterForbidden()
          return
        }
        setError(operationErrorMessage(reason, operationMode))
        setStatus('')
      }
    } finally {
      window.clearTimeout(timeoutId)
      if (isCurrentOperation()) {
        operationControllerRef.current = null
        operationAbortReasonRef.current = null
        setBusy(false)
      }
    }
  }

  function cancelOperation() {
    if (!busy || !operationControllerRef.current) return
    operationAbortReasonRef.current = 'cancelled'
    operationControllerRef.current.abort()
  }

  async function copyResult() {
    if (signingOut || !output) return
    const requestId = ++resultCopyRequestRef.current
    setResultCopyFeedback(null)
    if (!navigator.clipboard?.writeText) {
      if (resultCopyRequestRef.current !== requestId) return
      setResultCopyFeedback({ tone: 'error', message: resultCopyFallbackMessage('Clipboard access is unavailable') })
      return
    }
    try {
      await navigator.clipboard.writeText(output)
      if (resultCopyRequestRef.current !== requestId) return
      setResultCopyFeedback({
        tone: 'success',
        message: mode === 'decrypt' && !revealed ? 'Copied without revealing the value' : 'Copied',
      })
    } catch {
      if (resultCopyRequestRef.current !== requestId) return
      setResultCopyFeedback({ tone: 'error', message: resultCopyFallbackMessage('Clipboard access was blocked') })
    }
  }

  async function copyAnsibleSnippet() {
    if (signingOut || !output || (mode !== 'encrypt' && mode !== 'rotate') || !isValidAnsibleVariableIdentifier(ansibleVariableName)) return

    const requestId = ++snippetCopyRequestRef.current
    setSnippetCopyFeedback(null)
    let snippet: string
    try {
      snippet = formatAnsibleVaultSnippet(ansibleVariableName, output)
    } catch {
      if (snippetCopyRequestRef.current !== requestId) return
      setAnsibleSnippetFallback('')
      setSnippetCopyFeedback({ tone: 'error', message: 'Could not prepare the Ansible snippet; copy the result manually' })
      return
    }
    if (!navigator.clipboard?.writeText) {
      if (snippetCopyRequestRef.current !== requestId) return
      setAnsibleSnippetFallback(snippet)
      setSnippetCopyFeedback({ tone: 'error', message: 'Clipboard access is unavailable; copy the Ansible snippet manually' })
      return
    }
    try {
      await navigator.clipboard.writeText(snippet)
      if (snippetCopyRequestRef.current !== requestId) return
      setAnsibleSnippetFallback('')
      setSnippetCopyFeedback({ tone: 'success', message: 'Copied Ansible snippet' })
    } catch {
      if (snippetCopyRequestRef.current !== requestId) return
      setAnsibleSnippetFallback(snippet)
      setSnippetCopyFeedback({ tone: 'error', message: 'Clipboard access was blocked; copy the Ansible snippet manually' })
    }
  }

  function clearSensitiveStateForSignOut() {
    operationGenerationRef.current += 1
    const operationController = operationControllerRef.current
    operationControllerRef.current = null
    operationController?.abort()

    const profileLoadController = profileLoadControllerRef.current
    profileLoadControllerRef.current = null
    profileLoadController?.abort()

    const profileRefreshController = profileRefreshControllerRef.current
    profileRefreshControllerRef.current = null
    profileRefreshController?.abort()

    snippetCopyRequestRef.current += 1
    resultCopyRequestRef.current += 1
    valueRef.current = ''
    setBusy(false)
    setLoadingProfiles(false)
    setValue('')
    setOutput('')
    setAnsibleVariableName('')
    setAnsibleSnippetFallback('')
    setResultCopyFeedback(null)
    setSnippetCopyFeedback(null)
    setRevealed(false)
    setModeNotice('')
  }

  async function handleLogout() {
    if (signingOutRef.current || signedOut) return

    signingOutRef.current = true
    const controller = new AbortController()
    logoutControllerRef.current = controller
    const isCurrentLogout = () => logoutControllerRef.current === controller

    clearSensitiveStateForSignOut()
    setSigningOut(true)
    setLogoutFailed(false)
    setStatus('Signing out…')
    setError('')

    try {
      await logout(controller.signal)
      if (!isCurrentLogout()) return
      setSession(null)
      setProfiles([])
      setProfileSnapshotValid(false)
      setRecoveringStaleCapabilities(false)
      setProfileLoadFailed(false)
      setProfileLoadError('')
      setLoadFailureStage(null)
      setError('')
      setStatus('')
      setSignedOut(true)
    } catch (reason) {
      if (!isCurrentLogout()) return
      setStatus('')
      setLogoutFailed(true)
      setError(logoutErrorMessage(reason))
    } finally {
      if (isCurrentLogout()) {
        logoutControllerRef.current = null
        signingOutRef.current = false
        setSigningOut(false)
      }
    }
  }

  function clearAll() {
    if (workbenchLocked || !canClear) return
    operationGenerationRef.current += 1
    snippetCopyRequestRef.current += 1
    resultCopyRequestRef.current += 1
    setValue('')
    setOutput('')
    setAnsibleVariableName('')
    setAnsibleSnippetFallback('')
    setResultCopyFeedback(null)
    setSnippetCopyFeedback(null)
    setRevealed(false)
    setError('')
    if (!recoveringStaleCapabilities) setStatus('')
    setModeNotice('')
  }

  if (signedOut) {
    return (
      <div className="console-app signed-out-view">
        <header className="console-topbar">
          <div className="topbar-inner">
            <div className="brand-lockup">
              <img className="brand-mark" src="/vaultsmith-logo.png" alt="" width="32" height="32" />
              <span className="brand-name">Vaultsmith</span>
            </div>
          </div>
        </header>
        <main className="console-content">
          <section className="workbench-card signed-out-card" aria-labelledby="signed-out-heading">
            <div className="content-heading">
              <div className="heading-copy">
                <h1 id="signed-out-heading">Signed out</h1>
                <p>Your Vaultsmith session has ended. Sign in again when you are ready.</p>
              </div>
            </div>
            <button className="primary-button" type="button" onClick={redirectToLogin}>Sign in again</button>
          </section>
        </main>
      </div>
    )
  }

  return (
    <div className="console-app" data-mode={mode}>
      <header className="console-topbar">
        <div className="topbar-inner">
          <div className="brand-lockup">
            <img className="brand-mark" src="/vaultsmith-logo.png" alt="" width="32" height="32" />
            <span className="brand-name">Vaultsmith</span>
          </div>
          {session?.authenticated && (
            <div className="session-controls">
              {session.email && <span className="session-email">{session.email}</span>}
              <button className="quiet-button" type="button" onClick={() => void handleLogout()} disabled={signingOut}>
                {signingOut ? 'Signing out…' : logoutFailed ? 'Retry sign out' : 'Sign out'}
              </button>
            </div>
          )}
        </div>
      </header>

      <main className="console-content">
        <div className="content-heading">
          <div className="heading-copy">
            <h1>{heading}</h1>
            <p>{modeGuidance}</p>
          </div>
        </div>

        <section className="workbench-card" aria-label="Vault operation">
          <div className="global-feedback">
            <div className="status-slot">
              {status
                ? <p className="status-line" role="status" aria-live="polite">{status}</p>
                : <span className="feedback-placeholder" aria-hidden="true">&nbsp;</span>}
            </div>
            <div className="error-slot">
              {visibleError
                ? (
                  <div className="error-banner" role="alert">
                    <span>{visibleError}</span>
                    {profileLoadFailed && !logoutFailed && !loadingProfiles && <button className="secondary-button" type="button" onClick={retryProfiles} disabled={workbenchLocked}>{loadFailureStage === 'session' ? 'Retry loading session' : 'Retry loading environments'}</button>}
                  </div>
                )
                : <span className="feedback-placeholder" aria-hidden="true">&nbsp;</span>}
            </div>
          </div>

          <form
            className="operation-form"
            aria-label="Vault operation form"
            aria-busy={workbenchLocked}
            onSubmit={(event) => {
              event.preventDefault()
              void submit()
            }}
          >
            <div className="control-strip">
              {mode === 'rotate' ? (
                <div className="rotate-profile-fields">
                  <div className="field-label">
                    <label htmlFor="source-profile-select">From environment</label>
                    <select
                      id="source-profile-select"
                      value={profileId}
                      disabled={!profileSnapshotReady || workbenchLocked || decryptProfiles.length === 0}
                      onChange={(event) => changeProfile(event.target.value)}
                    >
                      {!profileIsEligible(decryptProfiles, profileId) && <option value="">Select an environment</option>}
                      {decryptProfiles.map((profile) => (
                        <option key={profile.id} value={profile.id}>{profile.label}</option>
                      ))}
                    </select>
                  </div>
                  <div className="field-label">
                    <label htmlFor="destination-profile-select">To environment</label>
                    <select
                      id="destination-profile-select"
                      value={destinationProfileId}
                      disabled={!profileSnapshotReady || workbenchLocked || encryptProfiles.length === 0}
                      onChange={(event) => changeDestinationProfile(event.target.value)}
                    >
                      {!profileIsEligible(encryptProfiles, destinationProfileId) && <option value="">Select an environment</option>}
                      {encryptProfiles.map((profile) => (
                        <option key={profile.id} value={profile.id}>{profile.label}</option>
                      ))}
                    </select>
                  </div>
                </div>
              ) : (
                <div className="field-label">
                  <label htmlFor="profile-select">Environment</label>
                  <select
                    id="profile-select"
                    value={profileId}
                    disabled={!profileSnapshotReady || workbenchLocked || eligibleProfiles.length === 0}
                    onChange={(event) => changeProfile(event.target.value)}
                  >
                    {!profileIsEligible(eligibleProfiles, profileId) && (
                      <option value="">{eligibleProfiles.length === 0 ? 'No environments available' : 'Select an environment'}</option>
                    )}
                    {eligibleProfiles.map((profile) => (
                      <option key={profile.id} value={profile.id}>{profile.label}</option>
                    ))}
                  </select>
                </div>
              )}

              <div className="operation-controls">
                <fieldset className="mode-fieldset">
                  <legend>Operation</legend>
                  <div className="mode-switch">
                    <button type="button" className={mode === 'encrypt' ? 'mode-button active' : 'mode-button'} aria-label="Set encrypt mode" aria-pressed={mode === 'encrypt'} onClick={() => changeMode('encrypt')} disabled={workbenchLocked || !profileSnapshotReady || !encryptAvailable}>Encrypt</button>
                    <button type="button" className={mode === 'decrypt' ? 'mode-button active' : 'mode-button'} aria-label="Set decrypt mode" aria-pressed={mode === 'decrypt'} onClick={() => changeMode('decrypt')} disabled={workbenchLocked || !profileSnapshotReady || !decryptAvailable}>Decrypt</button>
                    <button type="button" className={mode === 'rotate' ? 'mode-button active' : 'mode-button'} aria-label="Set re-key mode" aria-pressed={mode === 'rotate'} onClick={() => changeMode('rotate')} disabled={workbenchLocked || !profileSnapshotReady || !rotateAvailable}>Re-key</button>
                  </div>
                </fieldset>
                <div className="mode-availability-list" aria-label="Operation availability">
                  {profileSnapshotReady && (!encryptAvailable || !decryptAvailable || !rotateAvailable)
                    ? (
                      <>
                        {!encryptAvailable && <p>No environments are available for encryption.</p>}
                        {!decryptAvailable && <p>No environments are available for decryption.</p>}
                        {!rotateAvailable && <p>Re-key requires an available decrypt source and encrypt destination.</p>}
                      </>
                    )
                    : <span className="availability-placeholder" aria-hidden="true">&nbsp;</span>}
                </div>
              </div>
            </div>

            <div className="mode-notice-slot">
              {modeNotice ? <p className="mode-notice" aria-live="polite">{modeNotice}</p> : <span className="feedback-placeholder" aria-hidden="true">&nbsp;</span>}
            </div>

            <div className="editor-grid">
              <section className="editor-card" aria-label="Input editor">
                <div className="editor-card-header">
                  <label className="editor-caption" htmlFor="value-input">{inputName}</label>
                  <span className="editor-limit">{formatLimit(byteLimit)} max</span>
                </div>
                <textarea
                  id="value-input"
                  value={value}
                  onChange={(event) => changeValue(event.target.value)}
                  onPaste={handlePaste}
                  placeholder={mode === 'encrypt' ? 'Paste a value…' : 'Paste protected text or a YAML !vault block…'}
                  disabled={workbenchLocked || (!recoveringStaleCapabilities && (loadingProfiles || !modeAvailable) && value.length === 0)}
                  spellCheck={false}
                  autoComplete="off"
                  autoCorrect="off"
                  autoCapitalize="off"
                  aria-describedby={inputDescriptionIds}
                  rows={12}
                />
                <div className="editor-card-footer" id="input-byte-count"><span>Input size</span><strong>{byteLength.toLocaleString()} / {byteLimit.toLocaleString()} bytes</strong></div>
              </section>

              <section className="editor-card output-card" aria-label="Output editor">
                <div className="editor-card-header">
                  <label className="editor-caption" htmlFor="result-output">{outputName}</label>
                  <span className="editor-limit">Result</span>
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
                  placeholder="No result yet"
                />
                <div className="editor-card-footer" id="output-byte-count"><span>Result size</span><strong>{outputByteLength.toLocaleString()} bytes</strong></div>
              </section>
            </div>

            <div className="editor-aux-grid">
              <div className="auxiliary-slot input-auxiliary-slot">
                {formatInspection && value
                  ? (
                    <VaultFormatDiagnostics
                      inspection={formatInspection}
                      selectedProfileId={profileId}
                      selectedProfileLabel={selectedProfileLabel}
                      suggestedProfile={suggestedDecryptProfile}
                      suggestionDisabled={workbenchLocked}
                      onUseSuggestedProfile={useSuggestedDecryptProfile}
                    />
                  )
                  : <span className="auxiliary-placeholder" aria-hidden="true">&nbsp;</span>}
              </div>

              <div className="auxiliary-slot output-auxiliary-slot">
                {output && (mode === 'encrypt' || mode === 'rotate') && (
                  <div className="snippet-controls">
                    <div className="field-label">
                      <label htmlFor="ansible-variable-name">Ansible variable name</label>
                      <input
                        id="ansible-variable-name"
                        value={ansibleVariableName}
                        onChange={(event) => {
                          snippetCopyRequestRef.current += 1
                          setAnsibleVariableName(event.target.value)
                          setAnsibleSnippetFallback('')
                          setSnippetCopyFeedback(null)
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
                        aria-invalid={Boolean(ansibleVariableValidation)}
                        disabled={workbenchLocked}
                      />
                      <span className="field-help" id="ansible-variable-name-help">{ansibleVariableValidation || 'Use letters, numbers, and underscores. Start with a letter or underscore. Reserved Ansible names are not allowed.'}</span>
                    </div>
                    <button className="secondary-button" type="button" onClick={() => void copyAnsibleSnippet()} disabled={!canCopyAnsibleSnippet}>Copy Ansible snippet</button>
                    {snippetCopyFeedback && <span className={`copy-feedback ${snippetCopyFeedback.tone}`} role={snippetCopyFeedback.tone === 'error' ? 'alert' : 'status'}>{snippetCopyFeedback.message}</span>}
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
                {!output || (mode !== 'encrypt' && mode !== 'rotate') ? <span className="auxiliary-placeholder" aria-hidden="true">&nbsp;</span> : null}
              </div>
            </div>

            <div className="editor-actions-grid">
              <div className="panel-actions input-actions">
                <button className="primary-button" type="submit" disabled={!canSubmit}>
                  {busy ? operationProgressLabel(mode) : operationLabel(mode)}
                </button>
                {busy && <button className="secondary-button" type="button" onClick={cancelOperation}>Cancel</button>}
                <button className="quiet-button" type="button" onClick={clearAll} disabled={workbenchLocked || !canClear}>Clear values</button>
              </div>

              <div className="panel-actions output-actions">
                {output && !handoffEligible && <span className="result-handoff-notice" id="result-handoff-unavailable">{handoffUnavailableReason}</span>}
                {mode === 'decrypt' && output && <button className="secondary-button" type="button" disabled={workbenchLocked} onClick={() => { if (signingOut) return; setRevealed((current) => !current); setError(''); setResultCopyFeedback(null) }}>{revealed ? 'Hide result' : 'Reveal result'}</button>}
                <button className="secondary-button" type="button" onClick={useResultAsInput} aria-describedby={output && !handoffEligible ? 'result-handoff-unavailable' : undefined} disabled={!canUseResultAsInput}>{handoffLabel}</button>
                <button className="secondary-button" type="button" onClick={() => void copyResult()} disabled={copyDisabled}>{copyLabel}</button>
                {resultCopyFeedback && <span className={`copy-feedback ${resultCopyFeedback.tone}`} role={resultCopyFeedback.tone === 'error' ? 'alert' : 'status'}>{resultCopyFeedback.message}</span>}
              </div>
            </div>
          </form>
        </section>
      </main>
    </div>
  )
}

function operationLabel(mode: OperationMode): string {
  return mode === 'encrypt' ? 'Encrypt' : mode === 'decrypt' ? 'Decrypt' : 'Re-key'
}

function operationProgressLabel(mode: OperationMode): string {
  return mode === 'encrypt' ? 'Encrypting…' : mode === 'decrypt' ? 'Decrypting…' : 'Re-keying…'
}

function operationReadyLabel(mode: OperationMode): string {
  return mode === 'encrypt' ? 'Encrypted value ready' : mode === 'decrypt' ? 'Decrypted value ready' : 'Re-keyed value ready'
}

function modeIsAvailable(profiles: Profile[], mode: OperationMode): boolean {
  if (mode === 'rotate') {
    return profilesForMode(profiles, 'encrypt').length > 0 && profilesForMode(profiles, 'decrypt').length > 0
  }
  return profilesForMode(profiles, mode).length > 0
}

function preferredAvailableMode(profiles: Profile[]): OperationMode {
  if (modeIsAvailable(profiles, 'encrypt')) return 'encrypt'
  if (modeIsAvailable(profiles, 'decrypt')) return 'decrypt'
  if (modeIsAvailable(profiles, 'rotate')) return 'rotate'
  return 'encrypt'
}

function profilesForMode(profiles: Profile[], mode: OperationMode): Profile[] {
  const capability = mode === 'encrypt' ? 'encrypt' : 'decrypt'
  return profiles.filter((profile) => profile.capabilities[capability])
}

function profileIsEligible(profiles: Profile[], profileId: string): boolean {
  return profileId.length > 0 && profiles.some((profile) => profile.id === profileId)
}

function vaultIdSuggestedProfile(inspection: VaultFormatInspection, selectedProfileId: string, decryptProfiles: Profile[]): Profile | null {
  if (
    inspection.status !== 'recognized'
    || inspection.version !== '1.2'
    || inspection.cipher !== 'AES256'
    || !inspection.withinByteLimit
    || !inspection.label
    || inspection.label === selectedProfileId
    || inspection.issues.some((issue) => issue !== 'label-mismatch')
  ) return null

  return decryptProfiles.find((profile) => profile.id === inspection.label) ?? null
}

function VaultFormatDiagnostics({
  inspection,
  selectedProfileId,
  selectedProfileLabel,
  suggestedProfile,
  suggestionDisabled,
  onUseSuggestedProfile,
}: {
  inspection: VaultFormatInspection
  selectedProfileId: string
  selectedProfileLabel: string
  suggestedProfile: Profile | null
  suggestionDisabled: boolean
  onUseSuggestedProfile: (profileId: string) => void
}) {
  const state = inspection.status === 'recognized' && inspection.issues.length === 0 ? 'recognized' : 'warning'
  const guidance = formatGuidance(inspection, selectedProfileId, selectedProfileLabel)

  return (
    <section className="format-inspector" id="vault-format-diagnostics" data-state={state} aria-label="Vault format diagnostics">
      <div className="format-inspector-heading">
        <div className="format-inspector-title">
          <span>Vault format</span>
          <strong>{formatName(inspection)}</strong>
        </div>
        {suggestedProfile && (
          <button
            className="secondary-button format-inspector-action"
            type="button"
            disabled={suggestionDisabled}
            onClick={() => onUseSuggestedProfile(suggestedProfile.id)}
          >
            Use {suggestedProfile.label}
          </button>
        )}
      </div>
      <p className="format-inspector-note">Checks the header only; this does not verify encryption.</p>
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

function redirectToLogin(): void {
  if (typeof window === 'undefined') return
  const returnTo = `${window.location.pathname}${window.location.search}${window.location.hash}`
  window.location.assign(`/auth/login?return_to=${encodeURIComponent(returnTo || '/')}`)
}

function logoutErrorMessage(reason: unknown): string {
  if (reason instanceof ApiError) {
    if (reason.code === 'logout_timeout') {
      return 'Sign-out was not confirmed. The request timed out. Retry sign-out.'
    }
    if (reason.status === 503 || reason.code === 'not_ready') {
      return 'Sign-out was not confirmed. The service is unavailable. Retry sign-out.'
    }
    if (reason.code === 'network_error') {
      return 'Sign-out was not confirmed. The service could not be reached. Retry sign-out.'
    }
  }
  return 'Sign-out was not confirmed. Retry sign-out.'
}

function safeErrorMessage(reason: unknown, fallback: string, context: 'session' | 'profiles' | 'operation' = 'operation'): string {
  if (!(reason instanceof ApiError)) return fallback
  if (reason.code === 'network_error') return 'Unable to reach the Vaultsmith service'
  if (reason.code === 'session_timeout') return 'Session loading timed out. Check the service and try again.'
  if (reason.code === 'profiles_timeout') return 'Environment loading timed out. Check the service and try again.'
  if (reason.code === 'invalid_response') return 'The service returned an invalid response'
  if (reason.code === 'not_ready') return 'Vaultsmith service is not ready. Try again shortly.'
  if (reason.code === 'not_found') {
    if (context === 'session') return 'The session endpoint was not found. Check the service route and try again.'
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
      return 'Could not decrypt this value. Check the selected environment and paste protected text or a YAML !vault block.'
    }
    if (mode === 'rotate') {
      return 'Could not re-key this value. Check both selected environments and paste protected text or a YAML !vault block.'
    }
    return 'Could not encrypt this value. Check the selected environment and try again.'
  }
  return safeErrorMessage(reason, 'Value operation failed')
}

function formatLimit(bytes: number): string {
  return bytes === 1 << 20 ? '1 MiB' : '5 MiB'
}

function limitMessage(mode: OperationMode): string {
  return mode === 'encrypt' ? 'Value exceeds the 1 MiB limit' : 'Vault text exceeds the 5 MiB limit'
}
