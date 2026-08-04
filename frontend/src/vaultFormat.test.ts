import { describe, expect, it } from 'vitest'
import { MAX_VAULT_TEXT_BYTES, utf8ByteLength } from './api'
import { inspectVaultFormat, MAX_VAULT_LABEL_BYTES } from './vaultFormat'

describe('inspectVaultFormat', () => {
  it('accepts the app-provided UTF-8 byte length without recomputing it', () => {
    const inspection = inspectVaultFormat('$ANSIBLE_VAULT;1.1;AES256\nfixture', '', 123)

    expect(inspection.byteLength).toBe(123)
    expect(inspection.withinByteLimit).toBe(true)
  })
  it('recognizes an unlabeled Vault 1.1 header without inspecting the payload', () => {
    const value = '$ANSIBLE_VAULT;1.1;AES256\nfixture-ciphertext'
    const inspection = inspectVaultFormat(value, 'dev')

    expect(inspection).toMatchObject({
      status: 'recognized',
      version: '1.1',
      cipher: 'AES256',
      label: null,
      labelStatus: 'not-present',
      byteLength: utf8ByteLength(value),
      byteLimit: MAX_VAULT_TEXT_BYTES,
      withinByteLimit: true,
      issues: [],
    })
    expect(JSON.stringify(inspection)).not.toContain('fixture-ciphertext')
  })

  it('recognizes labeled and unlabeled Vault 1.2 headers', () => {
    const labeled = inspectVaultFormat('$ANSIBLE_VAULT;1.2;AES256;dev\nfixture', 'dev')
    const unlabeled = inspectVaultFormat('$ANSIBLE_VAULT;1.2;AES256\r\nfixture', 'dev')

    expect(labeled).toMatchObject({
      status: 'recognized',
      version: '1.2',
      cipher: 'AES256',
      label: 'dev',
      labelStatus: 'matches',
      issues: [],
    })
    expect(unlabeled).toMatchObject({
      status: 'recognized',
      version: '1.2',
      cipher: 'AES256',
      label: null,
      labelStatus: 'not-present',
      issues: [],
    })
  })

  it('keeps a bare-CR body out of the inspected label metadata', () => {
    const sentinel = 'bare-cr-body-sentinel'
    const inspection = inspectVaultFormat(`$ANSIBLE_VAULT;1.2;AES256;dev\r${sentinel}`, 'dev')

    expect(inspection).toMatchObject({
      status: 'malformed',
      label: null,
    })
    expect(inspection.issues).toContain('malformed-header')
    expect(JSON.stringify(inspection)).not.toContain(sentinel)
  })

  it('does not inspect body line endings after a valid header', () => {
    const inspection = inspectVaultFormat('$ANSIBLE_VAULT;1.1;AES256\nfixture\rbody')

    expect(inspection.status).toBe('recognized')
    expect(inspection.issues).not.toContain('malformed-header')
  })

  it('does not extract an unterminated label field as metadata', () => {
    const sentinel = 'unterminated-label-body-sentinel'
    const inspection = inspectVaultFormat(`$ANSIBLE_VAULT;1.2;AES256;dev${sentinel}`, 'dev')

    expect(inspection).toMatchObject({
      status: 'malformed',
      label: null,
    })
    expect(inspection.issues).toContain('malformed-header')
    expect(JSON.stringify(inspection)).not.toContain(sentinel)
  })

  it('bounds label metadata and omits unsafe labels', () => {
    const oversized = inspectVaultFormat(`$ANSIBLE_VAULT;1.2;AES256;${'x'.repeat(MAX_VAULT_LABEL_BYTES + 1)}\nfixture`)
    const unsafeLabel = `dev${String.fromCharCode(0x202e)}fixture`
    const unsafe = inspectVaultFormat(`$ANSIBLE_VAULT;1.2;AES256;${unsafeLabel}\nfixture`)
    const invisibleFormatLabel = `dev${String.fromCharCode(0x2061)}fixture`
    const invisibleFormat = inspectVaultFormat(`$ANSIBLE_VAULT;1.2;AES256;${invisibleFormatLabel}\nfixture`)
    const noncharacterLabel = `dev${String.fromCharCode(0xFFF0)}fixture`
    const noncharacter = inspectVaultFormat(`$ANSIBLE_VAULT;1.2;AES256;${noncharacterLabel}\nfixture`)
    const whitespace = inspectVaultFormat('$ANSIBLE_VAULT;1.2;AES256;dev \nfixture', 'dev')
    const backendWhitespace = inspectVaultFormat('$ANSIBLE_VAULT;1.2;AES256;\u0085dev\nfixture')
    const bomLabel = inspectVaultFormat('$ANSIBLE_VAULT;1.2;AES256;\uFEFFdev\nfixture')
    const markup = inspectVaultFormat('$ANSIBLE_VAULT;1.2;AES256;<b>dev</b>\nfixture')

    expect(oversized.label).toBeNull()
    expect(oversized.issues).toContain('label-too-long')
    expect(JSON.stringify(oversized)).not.toContain('x'.repeat(MAX_VAULT_LABEL_BYTES + 1))
    expect(unsafe.label).toBeNull()
    expect(unsafe.issues).toContain('label-unavailable')
    expect(JSON.stringify(unsafe)).not.toContain(unsafeLabel)
    expect(invisibleFormat.label).toBeNull()
    expect(invisibleFormat.issues).toContain('label-unavailable')
    expect(JSON.stringify(invisibleFormat)).not.toContain(invisibleFormatLabel)
    expect(noncharacter.label).toBeNull()
    expect(noncharacter.issues).toContain('label-unavailable')
    expect(JSON.stringify(noncharacter)).not.toContain(noncharacterLabel)
    expect(whitespace).toMatchObject({ status: 'malformed', label: null })
    expect(whitespace.issues).toContain('malformed-header')
    expect(backendWhitespace).toMatchObject({ status: 'malformed', label: null })
    expect(backendWhitespace.issues).toContain('malformed-header')
    expect(bomLabel).toMatchObject({ status: 'recognized', label: null })
    expect(bomLabel.issues).toContain('label-unavailable')
    expect(markup.label).toBe('<b>dev</b>')
  })

  it('reports a Vault ID label mismatch without blocking the operation', () => {
    const inspection = inspectVaultFormat('$ANSIBLE_VAULT;1.2;AES256;prod\nfixture', 'dev')

    expect(inspection).toMatchObject({
      status: 'recognized',
      label: 'prod',
      labelStatus: 'mismatch',
      withinByteLimit: true,
    })
    expect(inspection.issues).toContain('label-mismatch')
  })

  it('distinguishes missing, malformed, and unsupported headers', () => {
    const missing = inspectVaultFormat('plain input')
    const malformed = inspectVaultFormat('$ANSIBLE_VAULT;1.2;AES256;\nfixture')
    const malformedExtraField = inspectVaultFormat('$ANSIBLE_VAULT;1.2;AES256;dev;extra\nfixture')
    const missingVersion = inspectVaultFormat('$ANSIBLE_VAULT;;AES256\nfixture')
    const missingCipher = inspectVaultFormat('$ANSIBLE_VAULT;1.2\nfixture')
    const manyFields = inspectVaultFormat(`$ANSIBLE_VAULT;1.2;AES256${';'.repeat(100_000)}\nfixture`)
    const unterminated11 = inspectVaultFormat('$ANSIBLE_VAULT;1.1;AES256')
    const unterminated12 = inspectVaultFormat('$ANSIBLE_VAULT;1.2;AES256')
    const unsupportedVersion = inspectVaultFormat('$ANSIBLE_VAULT;1.3;AES256\nfixture')
    const unsupportedCipher = inspectVaultFormat('$ANSIBLE_VAULT;1.2;AES128\nfixture')

    expect(missing).toMatchObject({ status: 'malformed', version: null, cipher: null })
    expect(missing.issues).toContain('missing-header')
    expect(malformed).toMatchObject({ status: 'malformed', version: '1.2', cipher: 'AES256' })
    expect(malformed.issues).toContain('malformed-header')
    expect(malformedExtraField).toMatchObject({ status: 'malformed', version: '1.2', cipher: 'AES256' })
    expect(malformedExtraField.issues).toContain('malformed-header')
    expect(manyFields).toMatchObject({ status: 'malformed', version: '1.2', cipher: 'AES256' })
    expect(manyFields.issues).toContain('malformed-header')
    expect(missingVersion).toMatchObject({ status: 'malformed', version: null, cipher: 'AES256' })
    expect(missingVersion.issues).toContain('malformed-header')
    expect(missingCipher).toMatchObject({ status: 'malformed', version: '1.2', cipher: null })
    expect(missingCipher.issues).toContain('malformed-header')
    expect(unterminated11).toMatchObject({ status: 'malformed', version: '1.1', cipher: 'AES256' })
    expect(unterminated11.issues).toContain('malformed-header')
    expect(unterminated12).toMatchObject({ status: 'malformed', version: '1.2', cipher: 'AES256' })
    expect(unterminated12.issues).toContain('malformed-header')
    expect(unsupportedVersion).toMatchObject({ status: 'unsupported', version: 'unrecognized', cipher: 'AES256' })
    expect(unsupportedVersion.issues).toContain('unsupported-version')
    expect(unsupportedCipher).toMatchObject({ status: 'unsupported', version: '1.2', cipher: 'unrecognized' })
    expect(unsupportedCipher.issues).toContain('unsupported-cipher')
  })

  it('reports UTF-8 byte limits independently from header recognition', () => {
    const header = '$ANSIBLE_VAULT;1.1;AES256\n'
    const asciiPayloadLength = MAX_VAULT_TEXT_BYTES - header.length - 1
    const value = `${header}${'x'.repeat(asciiPayloadLength)}é`
    const expectedByteLength = header.length + asciiPayloadLength + 2 // é is 2 UTF-8 bytes
    const inspection = inspectVaultFormat(value)

    expect(inspection).toMatchObject({
      status: 'recognized',
      byteLength: expectedByteLength,
      byteLimit: MAX_VAULT_TEXT_BYTES,
      withinByteLimit: false,
    })
    expect(inspection.issues).toContain('over-limit')
  })

  it('returns an empty inspection without treating empty input as a malformed header', () => {
    expect(inspectVaultFormat('', 'dev')).toMatchObject({
      status: 'empty',
      version: null,
      cipher: null,
      label: null,
      labelStatus: 'not-present',
      byteLength: 0,
      withinByteLimit: true,
      issues: ['empty'],
    })
  })
})
