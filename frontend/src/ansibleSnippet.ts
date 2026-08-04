const ANSIBLE_VARIABLE_IDENTIFIER_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/
const ANSIBLE_VAULT_INDENT = ' '.repeat(10)
const RESERVED_ANSIBLE_VARIABLE_NAMES = new Set([
  'and', 'as', 'assert', 'async', 'await', 'break', 'class', 'continue', 'def',
  'del', 'elif', 'else', 'except', 'False', 'finally', 'for', 'from', 'global', 'if',
  'import', 'in', 'is', 'lambda', 'None', 'nonlocal', 'not', 'or', 'pass',
  'raise', 'return', 'True', 'try', 'while', 'with', 'yield',
])
const YAML_IMPLICIT_SCALAR_KEYS = new Set([
  'y', 'Y', 'yes', 'Yes', 'YES', 'n', 'N', 'no', 'No', 'NO',
  'true', 'True', 'TRUE', 'false', 'False', 'FALSE',
  'on', 'On', 'ON', 'off', 'Off', 'OFF', 'null', 'Null', 'NULL',
])
const YAML_UNSAFE_CIPHERTEXT_PATTERN = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u2028\u2029\uFFFE\uFFFF]/u

function hasYamlUnsafeCiphertext(ciphertext: string): boolean {
  if (YAML_UNSAFE_CIPHERTEXT_PATTERN.test(ciphertext)) return true

  for (let index = 0; index < ciphertext.length; index += 1) {
    const codePoint = ciphertext.charCodeAt(index)
    if (codePoint >= 0xD800 && codePoint <= 0xDBFF) {
      const nextCodePoint = ciphertext.charCodeAt(index + 1)
      if (nextCodePoint < 0xDC00 || nextCodePoint > 0xDFFF) return true
      index += 1
    } else if (codePoint >= 0xDC00 && codePoint <= 0xDFFF) {
      return true
    }
  }

  return false
}

/**
 * Returns true only for Ansible variable identifiers matching the documented
 * ASCII identifier grammar. The full-match comparison closes JavaScript's
 * final-newline behavior for `$` in the regular expression.
 */
export function isValidAnsibleVariableIdentifier(identifier: string): boolean {
  const match = ANSIBLE_VARIABLE_IDENTIFIER_PATTERN.exec(identifier)
  return match?.[0] === identifier && !RESERVED_ANSIBLE_VARIABLE_NAMES.has(identifier)
}

/**
 * Formats raw ciphertext without parsing or normalizing it.
 *
 * The marker line uses the first line ending found in the ciphertext (or LF
 * when the ciphertext has no line ending). Each ciphertext line receives ten
 * leading spaces, while its content and original line ending are preserved.
 */
export function formatAnsibleVaultSnippet(key: string, ciphertext: string): string {
  if (!isValidAnsibleVariableIdentifier(key)) {
    throw new Error('Invalid Ansible variable identifier')
  }

  if (hasYamlUnsafeCiphertext(ciphertext)) {
    throw new Error('Ciphertext contains YAML-unsafe characters')
  }

  const lineEnding = ciphertext.match(/\r\n|\n|\r/u)?.[0] ?? '\n'
  const yamlKey = YAML_IMPLICIT_SCALAR_KEYS.has(key) ? `'${key}'` : key
  return `${yamlKey}: !vault |${lineEnding}${indentCiphertext(ciphertext)}`
}

function indentCiphertext(ciphertext: string): string {
  let result = ''
  let lineStart = 0

  for (let index = 0; index < ciphertext.length; index += 1) {
    const character = ciphertext[index]
    if (character !== '\r' && character !== '\n') continue

    const lineEnd = character === '\r' && ciphertext[index + 1] === '\n' ? index + 2 : index + 1
    result += `${ANSIBLE_VAULT_INDENT}${ciphertext.slice(lineStart, lineEnd)}`
    lineStart = lineEnd
    index = lineEnd - 1
  }

  if (lineStart < ciphertext.length) {
    result += `${ANSIBLE_VAULT_INDENT}${ciphertext.slice(lineStart)}`
  }

  return result
}
