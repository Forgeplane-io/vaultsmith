import { MAX_VAULT_TEXT_BYTES, utf8ByteLength } from './api'

/**
 * Advisory header-only inspection. It never validates passwords, ciphertext, or cryptography.
 */
const VAULT_HEADER_PREFIX = '$ANSIBLE_VAULT'

/**
 * Maximum UTF-8 bytes exposed as Vault-ID metadata. Profile IDs are normally short;
 * rejecting larger labels avoids truncating potentially sensitive input into the UI.
 */
export const MAX_VAULT_LABEL_BYTES = 256
const UNSAFE_LABEL_PATTERN = /[\u0000-\u001F\u007F-\u009F\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180B-\u180F\u200B-\u200F\u202A-\u202E\u2060-\u206F\u3164\uFE00-\uFE0F\uFEFF\uFFA0\uFFF0-\uFFF8\u{1BCA0}-\u{1BCA3}\u{1D173}-\u{1D17A}\u{E0000}-\u{E0FFF}]/u

export type VaultFormatStatus = 'empty' | 'recognized' | 'malformed' | 'unsupported'
export type VaultFormatVersion = '1.1' | '1.2' | 'unrecognized' | null
export type VaultFormatCipher = 'AES256' | 'unrecognized' | null
export type VaultLabelStatus = 'not-present' | 'matches' | 'mismatch' | 'unverified'
export type VaultFormatIssue =
  | 'empty'
  | 'missing-header'
  | 'malformed-header'
  | 'unsupported-version'
  | 'unsupported-cipher'
  | 'label-mismatch'
  | 'label-too-long'
  | 'label-unavailable'
  | 'over-limit'

export type VaultFormatInspection = {
  status: VaultFormatStatus
  version: VaultFormatVersion
  cipher: VaultFormatCipher
  label: string | null
  labelStatus: VaultLabelStatus
  byteLength: number
  byteLimit: number
  withinByteLimit: boolean
  issues: VaultFormatIssue[]
}

export function inspectVaultFormat(value: string, selectedProfileId = '', precomputedByteLength?: number): VaultFormatInspection {
  const byteLength = precomputedByteLength ?? utf8ByteLength(value)
  const withinByteLimit = byteLength <= MAX_VAULT_TEXT_BYTES

  if (!value) {
    return {
      status: 'empty',
      version: null,
      cipher: null,
      label: null,
      labelStatus: 'not-present',
      byteLength,
      byteLimit: MAX_VAULT_TEXT_BYTES,
      withinByteLimit,
      issues: ['empty'],
    }
  }

  const issues: VaultFormatIssue[] = []
  if (!withinByteLimit) issues.push('over-limit')
  const firstLine = value.split(/[\r\n]/u, 1)[0]
  const hasBareCarriageReturn = value[firstLine.length] === '\r' && value[firstLine.length + 1] !== '\n'
  if (hasBareCarriageReturn) issues.unshift('malformed-header')

  const hasValidHeaderTerminator = value.slice(firstLine.length, firstLine.length + 2) === '\r\n'
    || value[firstLine.length] === '\n'
  const fields = splitHeaderFields(firstLine)
  if (fields[0] !== VAULT_HEADER_PREFIX) {
    issues.unshift('missing-header')
    return inspection({
      status: 'malformed',
      version: null,
      cipher: null,
      label: null,
      labelStatus: 'not-present',
      byteLength,
      withinByteLimit,
      issues,
    })
  }

  const version = toVersion(fields[1])
  const cipher = toCipher(fields[2])
  let label: string | null = null
  let malformed = hasBareCarriageReturn || !hasValidHeaderTerminator || fields.length < 3 || !fields[1] || !fields[2]

  if (version === '1.1') {
    malformed ||= fields.length !== 3
  } else if (version === '1.2') {
    if (fields.length === 3) {
      label = null
    } else if (fields.length === 4 && fields[3] && hasValidHeaderTerminator) {
      if (hasBackendTrimSpaceBoundary(fields[3])) {
        malformed = true
      } else {
        label = projectLabel(fields[3], issues)
      }
    } else {
      malformed = true
    }
  }

  if (malformed) {
    if (!issues.includes('malformed-header')) issues.unshift('malformed-header')
  } else {
    if (version === 'unrecognized') issues.unshift('unsupported-version')
    if (cipher === 'unrecognized') issues.unshift('unsupported-cipher')
  }

  const labelStatus = label
    ? selectedProfileId
      ? label === selectedProfileId ? 'matches' : 'mismatch'
      : 'unverified'
    : 'not-present'
  if (labelStatus === 'mismatch') issues.push('label-mismatch')

  const status: VaultFormatStatus = malformed
    ? 'malformed'
    : version === 'unrecognized' || cipher === 'unrecognized'
      ? 'unsupported'
      : 'recognized'

  return inspection({
    status,
    version,
    cipher,
    label,
    labelStatus,
    byteLength,
    withinByteLimit,
    issues,
  })
}

function hasBackendTrimSpaceBoundary(value: string): boolean {
  return isBackendTrimSpace(value.codePointAt(0)) || isBackendTrimSpace(value.codePointAt(value.length - 1))
}

function isBackendTrimSpace(codePoint: number | undefined): boolean {
  if (codePoint === undefined) return false
  return (codePoint >= 0x0009 && codePoint <= 0x000D)
    || codePoint === 0x0020
    || codePoint === 0x0085
    || codePoint === 0x00A0
    || codePoint === 0x1680
    || (codePoint >= 0x2000 && codePoint <= 0x200A)
    || (codePoint >= 0x2028 && codePoint <= 0x2029)
    || codePoint === 0x202F
    || codePoint === 0x205F
    || codePoint === 0x3000
}

function splitHeaderFields(value: string): string[] {
  const fields: string[] = []
  let fieldStart = 0

  for (let index = 0; index < value.length; index += 1) {
    if (value[index] !== ';') continue
    fields.push(value.slice(fieldStart, index))
    fieldStart = index + 1
    if (fields.length === 4) return [...fields, '']
  }

  fields.push(value.slice(fieldStart))
  return fields
}

function projectLabel(value: string, issues: VaultFormatIssue[]): string | null {
  if (utf8ByteLength(value) > MAX_VAULT_LABEL_BYTES) {
    issues.push('label-too-long')
    return null
  }
  if (UNSAFE_LABEL_PATTERN.test(value)) {
    issues.push('label-unavailable')
    return null
  }
  return value
}

function toVersion(value: string | undefined): VaultFormatVersion {
  if (value === '1.1' || value === '1.2') return value
  return value ? 'unrecognized' : null
}

function toCipher(value: string | undefined): VaultFormatCipher {
  if (value === 'AES256') return value
  return value ? 'unrecognized' : null
}

function inspection(fields: Omit<VaultFormatInspection, 'byteLimit'>): VaultFormatInspection {
  return {
    ...fields,
    byteLimit: MAX_VAULT_TEXT_BYTES,
  }
}
