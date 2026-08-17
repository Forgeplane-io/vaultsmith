import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import {
  ApiError,
  generateMaterial,
  OPERATION_TIMEOUT_MS,
  type GenerateKind,
  type GenerateRequest,
  type GenerateResponse,
  type GenerateSSHKeyAlgorithm,
  type GenerateX509KeyAlgorithm,
  type Profile,
} from './api'

type CopyFeedback = {
  tone: 'success' | 'error'
  message: string
}

type GenerateWorkbenchProps = {
  profiles: Profile[]
  profilesReady: boolean
  disabled: boolean
  modeSwitch: ReactNode
  externalStatus?: string
  externalError?: string
  externalRetryLabel?: string
  onRetryProfiles?: () => void
  onUnauthorized: () => void
  onForbidden: () => Promise<void>
  generate?: typeof generateMaterial
}

type X509Fields = {
  commonName: string
  serialNumber: string
  country: string
  organization: string
  organizationalUnit: string
  locality: string
  province: string
  streetAddress: string
  postalCode: string
  dnsNames: string
  ipAddresses: string
  emailAddresses: string
  uris: string
}

type GenerateX509Request = Extract<GenerateRequest, { kind: 'x509_csr' }>
type GenerateX509Subject = NonNullable<GenerateX509Request['parameters']['subject']>
type GenerateX509SANs = NonNullable<GenerateX509Request['parameters']['sans']>

const emptyX509Fields = (): X509Fields => ({
  commonName: '',
  serialNumber: '',
  country: '',
  organization: '',
  organizationalUnit: '',
  locality: '',
  province: '',
  streetAddress: '',
  postalCode: '',
  dnsNames: '',
  ipAddresses: '',
  emailAddresses: '',
  uris: '',
})

const repeatedSubjectFields = [
  ['country', 'Country'],
  ['organization', 'Organization'],
  ['organizationalUnit', 'Organizational unit'],
  ['locality', 'Locality'],
  ['province', 'Province / state'],
  ['streetAddress', 'Street address'],
  ['postalCode', 'Postal code'],
] as const

const sanFields = [
  ['dnsNames', 'DNS names'],
  ['ipAddresses', 'IP addresses'],
  ['emailAddresses', 'Email addresses'],
  ['uris', 'URIs'],
] as const

export default function GenerateWorkbench({
  profiles,
  profilesReady,
  disabled,
  modeSwitch,
  externalStatus = '',
  externalError = '',
  externalRetryLabel = 'Retry loading environments',
  onRetryProfiles,
  onUnauthorized,
  onForbidden,
  generate = generateMaterial,
}: GenerateWorkbenchProps) {
  const [profileId, setProfileId] = useState(profiles[0]?.id || '')
  const [kind, setKind] = useState<GenerateKind>('password')
  const [passwordLength, setPasswordLength] = useState(32)
  const [lowercase, setLowercase] = useState(true)
  const [uppercase, setUppercase] = useState(true)
  const [digits, setDigits] = useState(true)
  const [symbols, setSymbols] = useState(false)
  const [minLowercase, setMinLowercase] = useState(1)
  const [minUppercase, setMinUppercase] = useState(1)
  const [minDigits, setMinDigits] = useState(1)
  const [minSymbols, setMinSymbols] = useState(0)
  const [excludeAmbiguous, setExcludeAmbiguous] = useState(false)
  const [tokenEncoding, setTokenEncoding] = useState<'base64url' | 'hex'>('base64url')
  const [tokenBytes, setTokenBytes] = useState(32)
  const [sshAlgorithm, setSSHAlgorithm] = useState<GenerateSSHKeyAlgorithm>('ed25519')
  const [x509Algorithm, setX509Algorithm] = useState<GenerateX509KeyAlgorithm>('ecdsa_p256')
  const [x509, setX509] = useState<X509Fields>(emptyX509Fields)
  const [result, setResult] = useState<GenerateResponse | null>(null)
  const [busy, setBusy] = useState(false)
  const [status, setStatus] = useState('')
  const [error, setError] = useState('')
  const [copyFeedback, setCopyFeedback] = useState<CopyFeedback | null>(null)
  const requestControllerRef = useRef<AbortController | null>(null)
  const requestGenerationRef = useRef(0)
  const copyGenerationRef = useRef(0)

  const profileAvailable = profiles.some((profile) => profile.id === profileId)
  const validationError = useMemo(() => generationValidationError({
    profileAvailable,
    kind,
    passwordLength,
    lowercase,
    uppercase,
    digits,
    symbols,
    minLowercase,
    minUppercase,
    minDigits,
    minSymbols,
    tokenBytes,
    x509,
  }), [
    profileAvailable,
    kind,
    passwordLength,
    lowercase,
    uppercase,
    digits,
    symbols,
    minLowercase,
    minUppercase,
    minDigits,
    minSymbols,
    tokenBytes,
    x509,
  ])
  const locked = disabled || busy || !profilesReady
  const visibleError = error || externalError || validationError

  useEffect(() => {
    if (profileId === '' || profiles.some((profile) => profile.id === profileId)) return
    setProfileId('')
    clearResult()
  }, [profiles, profileId])

  useEffect(() => () => {
    requestGenerationRef.current += 1
    requestControllerRef.current?.abort()
    copyGenerationRef.current += 1
  }, [])

  function clearResult() {
    copyGenerationRef.current += 1
    setResult(null)
    setCopyFeedback(null)
    setError('')
    setStatus('')
  }

  function resetGenerateForm() {
    setKind('password')
    setPasswordLength(32)
    setLowercase(true)
    setUppercase(true)
    setDigits(true)
    setSymbols(false)
    setMinLowercase(1)
    setMinUppercase(1)
    setMinDigits(1)
    setMinSymbols(0)
    setExcludeAmbiguous(false)
    setTokenEncoding('base64url')
    setTokenBytes(32)
    setSSHAlgorithm('ed25519')
    setX509Algorithm('ecdsa_p256')
    setX509(emptyX509Fields())
    clearResult()
  }

  function changeKind(nextKind: GenerateKind) {
    if (locked) return
    setKind(nextKind)
    clearResult()
  }

  function changeKindSelection(value: string) {
    switch (value) {
      case 'password':
      case 'token':
      case 'ssh_keypair':
      case 'age_identity':
      case 'x509_csr':
        changeKind(value)
    }
  }

  function changeTokenEncoding(value: string) {
    if (value !== 'base64url' && value !== 'hex') return
    setTokenEncoding(value)
    clearResult()
  }

  function updateX509(field: keyof X509Fields, value: string) {
    if (locked) return
    setX509((current) => ({ ...current, [field]: value }))
    clearResult()
  }

  function updatePasswordClass(
    enabled: boolean,
    setEnabled: (value: boolean) => void,
    setMinimum: (value: number) => void,
  ) {
    setEnabled(enabled)
    setMinimum(enabled ? 1 : 0)
    clearResult()
  }

  function buildRequest(): GenerateRequest {
    switch (kind) {
      case 'password':
        return {
          kind,
          profileId,
          parameters: {
            length: passwordLength,
            lowercase,
            uppercase,
            digits,
            symbols,
            minLowercase,
            minUppercase,
            minDigits,
            minSymbols,
            excludeAmbiguous,
          },
        }
      case 'token':
        return { kind, profileId, parameters: { encoding: tokenEncoding, bytes: tokenBytes } }
      case 'ssh_keypair':
        return { kind, profileId, parameters: { algorithm: sshAlgorithm } }
      case 'age_identity':
        return { kind, profileId, parameters: {} }
      case 'x509_csr': {
        const subject = compactX509Subject(x509)
        const sans = compactX509SANs(x509)
        const request: GenerateX509Request = {
          kind,
          profileId,
          parameters: { algorithm: x509Algorithm },
        }
        if (subject) request.parameters.subject = subject
        if (sans) request.parameters.sans = sans
        return request
      }
    }
  }

  async function submit() {
    if (locked || validationError) return

    const controller = new AbortController()
    const generation = requestGenerationRef.current + 1
    requestGenerationRef.current = generation
    requestControllerRef.current = controller
    const isCurrent = () => requestGenerationRef.current === generation && requestControllerRef.current === controller
    const timeout = window.setTimeout(() => controller.abort(), OPERATION_TIMEOUT_MS)

    // A prior randomized result must not survive dispatch of another request.
    clearResult()
    setBusy(true)
    setStatus('Generating and sealing…')
    try {
      const generated = await generate(buildRequest(), controller.signal)
      if (!isCurrent() || controller.signal.aborted) return
      setResult(generated)
      setStatus('Sealed material ready')
    } catch (cause: unknown) {
      if (!isCurrent()) return
      if (controller.signal.aborted) {
        setError('Generation timed out. The result is unknown; do not retry automatically.')
        setStatus('')
      } else if (cause instanceof ApiError && cause.code === 'unauthorized') {
        onUnauthorized()
        setStatus('Sign-in required…')
      } else if (cause instanceof ApiError && cause.status === 403 && cause.code === 'forbidden') {
        setStatus('')
        await onForbidden()
      } else {
        setError(generateErrorMessage(cause))
        setStatus('')
      }
    } finally {
      window.clearTimeout(timeout)
      if (isCurrent()) {
        requestControllerRef.current = null
        setBusy(false)
      }
    }
  }

  async function copyText(value: string, successMessage: string) {
    const copyGeneration = copyGenerationRef.current + 1
    copyGenerationRef.current = copyGeneration
    setCopyFeedback(null)
    if (!navigator.clipboard?.writeText) {
      if (copyGenerationRef.current === copyGeneration) {
        setCopyFeedback({ tone: 'error', message: 'Clipboard access is unavailable; copy the value manually' })
      }
      return
    }
    try {
      await navigator.clipboard.writeText(value)
      if (copyGenerationRef.current === copyGeneration) {
        setCopyFeedback({ tone: 'success', message: successMessage })
      }
    } catch {
      if (copyGenerationRef.current === copyGeneration) {
        setCopyFeedback({ tone: 'error', message: 'Clipboard access was blocked; copy the value manually' })
      }
    }
  }

  function downloadPublic(value: string, filename: string) {
    setCopyFeedback(null)
    try {
      downloadPublicArtifact(value, filename)
      setCopyFeedback({ tone: 'success', message: `Downloaded ${filename}` })
    } catch {
      setCopyFeedback({ tone: 'error', message: 'The public artifact could not be downloaded; copy it manually' })
    }
  }

  return (
    <>
      <div className="global-feedback">
        <div className="status-slot">
          {(status || externalStatus)
            ? <p className="status-line" role="status" aria-live="polite">{status || externalStatus}</p>
            : <span className="feedback-placeholder" aria-hidden="true">&nbsp;</span>}
        </div>
      </div>

      <form
        className="operation-form generate-form"
        aria-label="Generate material form"
        aria-busy={locked}
        onSubmit={(event) => {
          event.preventDefault()
          void submit()
        }}
      >
        <div className="generate-control-strip">
          <div className="field-label">
            <label htmlFor="generate-profile">Environment</label>
            <select
              id="generate-profile"
              value={profileId}
              disabled={locked || !profilesReady || profiles.length === 0}
              onChange={(event) => { setProfileId(event.target.value); clearResult() }}
            >
              {!profileAvailable && <option value="">{profiles.length === 0 ? 'No environments available' : 'Select an environment'}</option>}
              {profiles.map((profile) => <option key={profile.id} value={profile.id}>{profile.label}</option>)}
            </select>
          </div>
          <div className="field-label">
            <label htmlFor="generate-kind">Material</label>
            <select id="generate-kind" value={kind} disabled={locked} onChange={(event) => changeKindSelection(event.target.value)}>
              <option value="password">Password</option>
              <option value="token">Random token</option>
              <option value="ssh_keypair">SSH keypair</option>
              <option value="age_identity">age identity</option>
              <option value="x509_csr">X.509 key and CSR</option>
            </select>
          </div>
          <div className="operation-controls">
            <fieldset className="mode-fieldset" disabled={locked}>
              <legend>Operation</legend>
              {modeSwitch}
            </fieldset>
          </div>
        </div>

        <section className="generate-parameters" aria-labelledby="generate-parameters-heading">
          <div className="generate-section-heading">
            <div>
              <h2 id="generate-parameters-heading">Generation settings</h2>
              <p>Private material is generated on the server and returned only as sealed Vault text.</p>
            </div>
          </div>

          {kind === 'password' && (
            <div className="generate-settings-grid">
              <NumberField id="password-length" label="Length" value={passwordLength} min={22} max={128} disabled={locked} onChange={(value) => { setPasswordLength(value); clearResult() }} />
              <NumberField id="minimum-lowercase" label="Minimum lowercase" value={minLowercase} min={0} max={32} disabled={locked || !lowercase} onChange={(value) => { setMinLowercase(value); clearResult() }} />
              <NumberField id="minimum-uppercase" label="Minimum uppercase" value={minUppercase} min={0} max={32} disabled={locked || !uppercase} onChange={(value) => { setMinUppercase(value); clearResult() }} />
              <NumberField id="minimum-digits" label="Minimum digits" value={minDigits} min={0} max={32} disabled={locked || !digits} onChange={(value) => { setMinDigits(value); clearResult() }} />
              <NumberField id="minimum-symbols" label="Minimum symbols" value={minSymbols} min={0} max={32} disabled={locked || !symbols} onChange={(value) => { setMinSymbols(value); clearResult() }} />
              <div className="generate-checkboxes" role="group" aria-label="Password character classes">
                <Checkbox label="Lowercase" checked={lowercase} disabled={locked} onChange={(value) => updatePasswordClass(value, setLowercase, setMinLowercase)} />
                <Checkbox label="Uppercase" checked={uppercase} disabled={locked} onChange={(value) => updatePasswordClass(value, setUppercase, setMinUppercase)} />
                <Checkbox label="Digits" checked={digits} disabled={locked} onChange={(value) => updatePasswordClass(value, setDigits, setMinDigits)} />
                <Checkbox label="Symbols" checked={symbols} disabled={locked} onChange={(value) => updatePasswordClass(value, setSymbols, setMinSymbols)} />
                <Checkbox label="Exclude ambiguous characters" checked={excludeAmbiguous} disabled={locked} onChange={(value) => { setExcludeAmbiguous(value); clearResult() }} />
              </div>
            </div>
          )}

          {kind === 'token' && (
            <div className="generate-settings-grid compact">
              <div className="field-label">
                <label htmlFor="token-encoding">Encoding</label>
                <select id="token-encoding" value={tokenEncoding} disabled={locked} onChange={(event) => changeTokenEncoding(event.target.value)}>
                  <option value="base64url">Base64url (unpadded)</option>
                  <option value="hex">Hex (lowercase)</option>
                </select>
              </div>
              <NumberField id="token-bytes" label="Random bytes" value={tokenBytes} min={16} max={64} disabled={locked} onChange={(value) => { setTokenBytes(value); clearResult() }} />
            </div>
          )}

          {kind === 'ssh_keypair' && (
            <AlgorithmField
              id="ssh-algorithm"
              label="SSH algorithm"
              value={sshAlgorithm}
              disabled={locked}
              onChange={(value) => { setSSHAlgorithm(value); clearResult() }}
              options={[
                ['ed25519', 'Ed25519 — recommended'],
                ['ecdsa_p256', 'ECDSA P-256 — compatibility'],
                ['rsa_3072', 'RSA 3072 — compatibility'],
                ['rsa_4096', 'RSA 4096 — compatibility'],
              ]}
            />
          )}

          {kind === 'age_identity' && (
            <div className="fixed-parameter">
              <span>Algorithm</span>
              <strong>X25519</strong>
              <p>age identities use the native X25519 identity and recipient format.</p>
            </div>
          )}

          {kind === 'x509_csr' && (
            <div className="x509-settings">
              <AlgorithmField
                id="x509-algorithm"
                label="Private-key algorithm"
                value={x509Algorithm}
                disabled={locked}
                onChange={(value) => { setX509Algorithm(value); clearResult() }}
                options={[
                  ['ecdsa_p256', 'ECDSA P-256 — recommended compatibility choice'],
                  ['ed25519', 'Ed25519 — modern'],
                  ['ecdsa_p384', 'ECDSA P-384 — compatibility'],
                  ['rsa_3072', 'RSA 3072 — compatibility'],
                  ['rsa_4096', 'RSA 4096 — compatibility'],
                ]}
              />
              <p className="field-help compatibility-note">ECDSA and RSA are compatibility choices. Algorithm selection is not a compliance statement.</p>
              <fieldset className="x509-fieldset">
                <legend>Subject</legend>
                <div className="generate-settings-grid">
                  <TextField id="x509-common-name" label="Common name" value={x509.commonName} disabled={locked} onChange={(value) => updateX509('commonName', value)} />
                  <TextField id="x509-serial-number" label="Serial number" value={x509.serialNumber} disabled={locked} onChange={(value) => updateX509('serialNumber', value)} />
                  {repeatedSubjectFields.map(([field, label]) => (
                    <LineListField key={field} id={`x509-${field}`} label={label} value={x509[field]} disabled={locked} onChange={(value) => updateX509(field, value)} />
                  ))}
                </div>
              </fieldset>
              <fieldset className="x509-fieldset">
                <legend>Subject alternative names</legend>
                <div className="generate-settings-grid">
                  {sanFields.map(([field, label]) => (
                    <LineListField key={field} id={`x509-${field}`} label={label} value={x509[field]} disabled={locked} onChange={(value) => updateX509(field, value)} />
                  ))}
                </div>
              </fieldset>
              <p className="field-help">Enter one value per line. A common name or at least one SAN is required. Certificate policy remains with your CA.</p>
            </div>
          )}
        </section>

        <div className="generate-submit-row">
          <button className="primary-button" type="submit" disabled={locked || Boolean(validationError)}>{busy ? 'Generating and sealing…' : 'Generate sealed material'}</button>
          <button className="quiet-button" type="button" disabled={locked} onClick={resetGenerateForm}>Clear Generate form</button>
          <span className="field-help">This randomized operation is not retried automatically.</span>
        </div>

        {result && (
          <GenerateResult
            result={result}
            disabled={locked}
            copyFeedback={copyFeedback}
            onCopy={(value, message) => void copyText(value, message)}
            onDownload={downloadPublic}
          />
        )}
      </form>

      <div className="error-slot">
        {visibleError
          ? (
            <div className="error-banner" role="alert">
              <span>{visibleError}</span>
              {externalError && onRetryProfiles && (
                <button className="secondary-button" type="button" onClick={onRetryProfiles} disabled={disabled || busy}>{externalRetryLabel}</button>
              )}
            </div>
            )
          : <span className="feedback-placeholder" aria-hidden="true">&nbsp;</span>}
      </div>
    </>
  )
}

function GenerateResult({
  result,
  disabled,
  copyFeedback,
  onCopy,
  onDownload,
}: {
  result: GenerateResponse
  disabled: boolean
  copyFeedback: CopyFeedback | null
  onCopy: (value: string, successMessage: string) => void
  onDownload: (value: string, filename: string) => void
}) {
  const publicArtifact = result.kind === 'ssh_keypair'
    ? { label: 'SSH public key', value: result.public.authorizedKey, filename: 'vaultsmith-ssh-public-key.pub' }
    : result.kind === 'age_identity'
      ? { label: 'age recipient', value: result.public.recipient, filename: 'vaultsmith-age-recipient.txt' }
      : result.kind === 'x509_csr'
        ? { label: 'PKCS#10 CSR', value: result.public.csrPem, filename: 'vaultsmith-request.csr.pem' }
        : null
  const fingerprint = result.kind === 'ssh_keypair' || result.kind === 'x509_csr' ? result.public.fingerprint : null

  return (
    <section className="generate-result" aria-labelledby="generate-result-heading">
      <div className="generate-section-heading">
        <div>
          <h2 id="generate-result-heading">Sealed result</h2>
          <p>The private material is only inside this Vault ciphertext.</p>
        </div>
        <span className="result-kind">{materialLabel(result.kind)}</span>
      </div>

      <div className="generate-result-grid">
        <div className="generate-result-column">
          <div className="field-label">
            <label htmlFor="generated-vault-text">Sealed Vault value</label>
            <textarea id="generated-vault-text" value={result.secret.vaultText} readOnly rows={10} spellCheck={false} />
          </div>
          <div className="panel-actions">
            <button className="secondary-button" type="button" disabled={disabled} onClick={() => onCopy(result.secret.vaultText, 'Copied sealed Vault value')}>Copy sealed Vault value</button>
          </div>
        </div>

        <div className="generate-result-column">
          <EffectiveParameters result={result} />
          {publicArtifact && (
            <div className="public-artifact">
              <div className="field-label">
                <label htmlFor="generated-public-artifact">{publicArtifact.label}</label>
                <textarea id="generated-public-artifact" value={publicArtifact.value} readOnly rows={6} spellCheck={false} />
              </div>
              <div className="panel-actions">
                <button className="secondary-button" type="button" disabled={disabled} onClick={() => onCopy(publicArtifact.value, `Copied ${publicArtifact.label}`)}>Copy {publicArtifact.label}</button>
                <button className="secondary-button" type="button" disabled={disabled} onClick={() => onDownload(publicArtifact.value, publicArtifact.filename)}>Download {publicArtifact.label}</button>
              </div>
            </div>
          )}
          {fingerprint && (
            <div className="fingerprint-row">
              <div className="field-label">
                <label htmlFor="generated-fingerprint">SHA-256 fingerprint</label>
                <input id="generated-fingerprint" value={fingerprint} readOnly />
              </div>
              <button className="secondary-button" type="button" disabled={disabled} onClick={() => onCopy(fingerprint, 'Copied fingerprint')}>Copy fingerprint</button>
            </div>
          )}
          {copyFeedback && <p className={`copy-feedback ${copyFeedback.tone}`} role={copyFeedback.tone === 'error' ? 'alert' : 'status'}>{copyFeedback.message}</p>}
        </div>
      </div>
    </section>
  )
}

function EffectiveParameters({ result }: { result: GenerateResponse }) {
  const entries: Array<[string, string]> = result.kind === 'password'
    ? [
      ['Length', String(result.effectiveParameters.length)],
      ['Lowercase', yesNo(result.effectiveParameters.lowercase)],
      ['Uppercase', yesNo(result.effectiveParameters.uppercase)],
      ['Digits', yesNo(result.effectiveParameters.digits)],
      ['Symbols', yesNo(result.effectiveParameters.symbols)],
      ['Minimums', `${result.effectiveParameters.minLowercase} lower · ${result.effectiveParameters.minUppercase} upper · ${result.effectiveParameters.minDigits} digits · ${result.effectiveParameters.minSymbols} symbols`],
      ['Ambiguous characters excluded', yesNo(result.effectiveParameters.excludeAmbiguous)],
    ]
    : result.kind === 'token'
      ? [['Encoding', result.effectiveParameters.encoding], ['Random bytes', String(result.effectiveParameters.bytes)]]
      : [['Algorithm', algorithmLabel(result.effectiveParameters.algorithm)]]

  return (
    <dl className="effective-parameters" aria-label="Effective parameters">
      {entries.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}
    </dl>
  )
}

function NumberField({ id, label, value, min, max, disabled, onChange }: {
  id: string
  label: string
  value: number
  min: number
  max: number
  disabled: boolean
  onChange: (value: number) => void
}) {
  return (
    <div className="field-label">
      <label htmlFor={id}>{label}</label>
      <input id={id} type="number" value={value} min={min} max={max} step={1} disabled={disabled} onChange={(event) => onChange(event.target.valueAsNumber)} />
    </div>
  )
}

function TextField({ id, label, value, disabled, onChange }: {
  id: string
  label: string
  value: string
  disabled: boolean
  onChange: (value: string) => void
}) {
  return (
    <div className="field-label">
      <label htmlFor={id}>{label}</label>
      <input id={id} value={value} disabled={disabled} autoComplete="off" spellCheck={false} onChange={(event) => onChange(event.target.value)} />
    </div>
  )
}

function LineListField({ id, label, value, disabled, onChange }: {
  id: string
  label: string
  value: string
  disabled: boolean
  onChange: (value: string) => void
}) {
  return (
    <div className="field-label">
      <label htmlFor={id}>{label}</label>
      <textarea id={id} className="generate-list-input" value={value} disabled={disabled} rows={3} spellCheck={false} placeholder="One value per line" onChange={(event) => onChange(event.target.value)} />
    </div>
  )
}

function Checkbox({ label, checked, disabled, onChange }: {
  label: string
  checked: boolean
  disabled: boolean
  onChange: (checked: boolean) => void
}) {
  return <label className="checkbox-label"><input type="checkbox" checked={checked} disabled={disabled} onChange={(event) => onChange(event.target.checked)} /><span>{label}</span></label>
}

function AlgorithmField<Value extends string>({ id, label, value, disabled, onChange, options }: {
  id: string
  label: string
  value: Value
  disabled: boolean
  onChange: (value: Value) => void
  options: ReadonlyArray<readonly [Value, string]>
}) {
  return (
    <div className="field-label algorithm-field">
      <label htmlFor={id}>{label}</label>
      <select
        id={id}
        value={value}
        disabled={disabled}
        onChange={(event) => {
          const selected = options.find(([optionValue]) => optionValue === event.target.value)
          if (selected) onChange(selected[0])
        }}
      >
        {options.map(([optionValue, optionLabel]) => <option key={optionValue} value={optionValue}>{optionLabel}</option>)}
      </select>
    </div>
  )
}

function compactX509Subject(fields: X509Fields): GenerateX509Subject | undefined {
  const subject: GenerateX509Subject = {}
  if (fields.commonName !== '') subject.commonName = fields.commonName
  if (fields.serialNumber !== '') subject.serialNumber = fields.serialNumber

  const country = splitLines(fields.country)
  if (country.length > 0) subject.country = country
  const organization = splitLines(fields.organization)
  if (organization.length > 0) subject.organization = organization
  const organizationalUnit = splitLines(fields.organizationalUnit)
  if (organizationalUnit.length > 0) subject.organizationalUnit = organizationalUnit
  const locality = splitLines(fields.locality)
  if (locality.length > 0) subject.locality = locality
  const province = splitLines(fields.province)
  if (province.length > 0) subject.province = province
  const streetAddress = splitLines(fields.streetAddress)
  if (streetAddress.length > 0) subject.streetAddress = streetAddress
  const postalCode = splitLines(fields.postalCode)
  if (postalCode.length > 0) subject.postalCode = postalCode

  return Object.keys(subject).length > 0 ? subject : undefined
}

function compactX509SANs(fields: X509Fields): GenerateX509SANs | undefined {
  const sans: GenerateX509SANs = {}
  const dnsNames = splitLines(fields.dnsNames)
  if (dnsNames.length > 0) sans.dnsNames = dnsNames
  const ipAddresses = splitLines(fields.ipAddresses)
  if (ipAddresses.length > 0) sans.ipAddresses = ipAddresses
  const emailAddresses = splitLines(fields.emailAddresses)
  if (emailAddresses.length > 0) sans.emailAddresses = emailAddresses
  const uris = splitLines(fields.uris)
  if (uris.length > 0) sans.uris = uris

  return Object.keys(sans).length > 0 ? sans : undefined
}

function splitLines(value: string): string[] {
  return value === '' ? [] : value.split('\n')
}

function hasEmptyLine(value: string): boolean {
  return value !== '' && splitLines(value).some((line) => line === '')
}

function generationValidationError(input: {
  profileAvailable: boolean
  kind: GenerateKind
  passwordLength: number
  lowercase: boolean
  uppercase: boolean
  digits: boolean
  symbols: boolean
  minLowercase: number
  minUppercase: number
  minDigits: number
  minSymbols: number
  tokenBytes: number
  x509: X509Fields
}): string {
  if (!input.profileAvailable) return 'Select an environment available for encryption.'
  if (input.kind === 'password') {
    if (!Number.isInteger(input.passwordLength) || input.passwordLength < 22 || input.passwordLength > 128) return 'Password length must be from 22 to 128 characters.'
    const classes = [input.lowercase, input.uppercase, input.digits, input.symbols]
    const minima = [input.minLowercase, input.minUppercase, input.minDigits, input.minSymbols]
    if (!classes.some(Boolean)) return 'Enable at least one password character class.'
    if (!minima.every((minimum) => Number.isInteger(minimum) && minimum >= 0 && minimum <= 32)) return 'Password class minimums must be from 0 to 32.'
    if (minima.some((minimum, index) => !classes[index] && minimum !== 0)) return 'A disabled password class must have a minimum of zero.'
    if (minima.reduce((sum, minimum) => sum + minimum, 0) > input.passwordLength) return 'Password class minimums cannot exceed the requested length.'
  }
  if (input.kind === 'token' && (!Number.isInteger(input.tokenBytes) || input.tokenBytes < 16 || input.tokenBytes > 64)) {
    return 'Token size must be from 16 to 64 random bytes.'
  }
  if (input.kind === 'x509_csr') {
    if ([...repeatedSubjectFields, ...sanFields].some(([field]) => hasEmptyLine(input.x509[field]))) {
      return 'X.509 multi-value fields cannot contain empty rows.'
    }
    const hasCommonName = input.x509.commonName !== ''
    const hasSAN = sanFields.some(([field]) => splitLines(input.x509[field]).length > 0)
    if (!hasCommonName && !hasSAN) return 'Enter a common name or at least one subject alternative name.'
  }
  return ''
}

function generateErrorMessage(cause: unknown): string {
  if (!(cause instanceof ApiError)) return 'Material generation failed. The result is unknown; do not retry automatically.'
  if (cause.code === 'invalid_response') return 'The service returned an invalid Generate response. The result is unknown; do not retry automatically.'
  if (cause.code === 'invalid_request') return 'The request was not accepted. Review the generation settings.'
  if (cause.code === 'operation_failed') return 'Material generation or Vault sealing failed. Do not retry automatically.'
  if (cause.code === 'not_found') return 'The selected environment is no longer available. Reload environments and try again.'
  if (cause.code === 'network_error' || cause.code === 'temporarily_unavailable' || cause.code === 'not_ready' || cause.status >= 500) {
    return 'Vaultsmith is temporarily unavailable. The result is unknown; do not retry automatically.'
  }
  return 'Material generation failed. The result is unknown; do not retry automatically.'
}

export function normalizePublicDownload(value: string): string {
  return value.replace(/(?:\r\n|\r|\n)+$/u, '') + '\n'
}

export function downloadPublicArtifact(value: string, filename: string): void {
  const blob = new Blob([normalizePublicDownload(value)], { type: 'text/plain;charset=utf-8' })
  const objectURL = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = objectURL
  anchor.download = filename
  anchor.hidden = true
  document.body.append(anchor)
  try {
    anchor.click()
  } finally {
    anchor.remove()
    URL.revokeObjectURL(objectURL)
  }
}

function materialLabel(kind: GenerateKind): string {
  switch (kind) {
    case 'password': return 'Password'
    case 'token': return 'Random token'
    case 'ssh_keypair': return 'SSH keypair'
    case 'age_identity': return 'age identity'
    case 'x509_csr': return 'X.509 key and CSR'
  }
}

function algorithmLabel(algorithm: string): string {
  switch (algorithm) {
    case 'ed25519': return 'Ed25519'
    case 'ecdsa_p256': return 'ECDSA P-256'
    case 'ecdsa_p384': return 'ECDSA P-384'
    case 'rsa_3072': return 'RSA 3072'
    case 'rsa_4096': return 'RSA 4096'
    case 'x25519': return 'X25519'
    default: return algorithm
  }
}

function yesNo(value: boolean): string {
  return value ? 'Yes' : 'No'
}
