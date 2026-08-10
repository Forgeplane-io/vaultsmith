import { describe, expect, it } from 'vitest'
import { ansibleVariableValidationMessage, formatAnsibleVaultSnippet, isValidAnsibleVariableIdentifier } from './ansibleSnippet'

const INDENT = ' '.repeat(10)
const VAULT_1_2_CIPHERTEXT = [
  '$ANSIBLE_VAULT;1.2;AES256;dev',
  '00112233445566778899aabbccddeeff',
  'ffeeddccbbaa99887766554433221100',
].join('\n')

describe('Ansible Vault snippet helpers', () => {
  it('accepts a valid identifier and formats a Vault 1.2 ciphertext deterministically', () => {
    expect(isValidAnsibleVariableIdentifier('db_password')).toBe(true)

    expect(formatAnsibleVaultSnippet('db_password', VAULT_1_2_CIPHERTEXT)).toBe(
      [
        'db_password: !vault |',
        `${INDENT}$ANSIBLE_VAULT;1.2;AES256;dev`,
        `${INDENT}00112233445566778899aabbccddeeff`,
        `${INDENT}ffeeddccbbaa99887766554433221100`,
      ].join('\n'),
    )
  })

  it.each(['yes', 'on', 'null', 'TRUE'])('quotes YAML implicit scalar key %j', (key) => {
    expect(isValidAnsibleVariableIdentifier(key)).toBe(true)
    expect(formatAnsibleVaultSnippet(key, VAULT_1_2_CIPHERTEXT)).toMatch(new RegExp(`^'${key}': !vault \\|`))
  })
  it('reports the first useful validation message for common invalid names', () => {
    expect(ansibleVariableValidationMessage('1password')).toBe('Start with a letter or underscore.')
    expect(ansibleVariableValidationMessage('-password')).toBe('Start with a letter or underscore.')
    expect(ansibleVariableValidationMessage('db-password')).toBe('Variable names cannot contain hyphens.')
    expect(ansibleVariableValidationMessage('class')).toBe('This name is reserved by Ansible.')
    expect(ansibleVariableValidationMessage('db_password')).toBe('')
  })

  it('preserves Python-reserved Ansible variable names', () => {
    for (const key of ['class', 'for', 'True', 'False', 'None', 'await']) {
      expect(isValidAnsibleVariableIdentifier(key)).toBe(false)
      expect(() => formatAnsibleVaultSnippet(key, VAULT_1_2_CIPHERTEXT)).toThrow('Invalid Ansible variable identifier')
    }
  })
  it.each(['case', 'match'])('accepts Python soft keyword %j as an identifier', (key) => {
    expect(isValidAnsibleVariableIdentifier(key)).toBe(true)
    expect(formatAnsibleVaultSnippet(key, VAULT_1_2_CIPHERTEXT)).toMatch(new RegExp(`^${key}: !vault \\|`))
  })

  it.each([
    '1password',
    'db-password',
    'db.password',
    'db password',
    '\tdb_password',
    'db_password ',
    'db_password\n',
    'db_password: !vault |',
    'db_password\nother: value',
    '!vault',
  ])('rejects unsafe identifier %j without formatting it', (key) => {
    expect(isValidAnsibleVariableIdentifier(key)).toBe(false)
    expect(() => formatAnsibleVaultSnippet(key, VAULT_1_2_CIPHERTEXT)).toThrow(
      'Invalid Ansible variable identifier',
    )
  })

  it('preserves every ciphertext line, including mixed CRLF/LF endings and content spaces', () => {
    const ciphertext =
      '$ANSIBLE_VAULT;1.2;AES256;prod\r\nfirst-line\r\n  second-line-with-leading-spaces\nlast-line\r\n'

    expect(formatAnsibleVaultSnippet('secret_key', ciphertext)).toBe(
      `secret_key: !vault |\r\n${INDENT}$ANSIBLE_VAULT;1.2;AES256;prod\r\n${INDENT}first-line\r\n${INDENT}  second-line-with-leading-spaces\n${INDENT}last-line\r\n`,
    )
  })

  it('rejects YAML-normalized line breaks, forbidden controls, noncharacters, and unpaired surrogates in ciphertext', () => {
    for (const character of [
      '\u0085',
      '\u2028',
      '\u2029',
      '\u0000',
      '\u0001',
      '\uFFFE',
      '\uFFFF',
      String.fromCharCode(0xD800),
    ]) {
      const ciphertext = `$ANSIBLE_VAULT;1.2;AES256;prod\npayload-one${character}payload-two`

      expect(() => formatAnsibleVaultSnippet('secret_key', ciphertext)).toThrow(
        'Ciphertext contains YAML-unsafe characters',
      )
    }
  })

  it('preserves valid paired astral characters in ciphertext', () => {
    const character = String.fromCodePoint(0x1F600)
    const ciphertext = `$ANSIBLE_VAULT;1.2;AES256;prod\npayload-one${character}payload-two`

    expect(formatAnsibleVaultSnippet('secret_key', ciphertext)).toContain(
      `${INDENT}payload-one${character}payload-two`,
    )
  })
})
