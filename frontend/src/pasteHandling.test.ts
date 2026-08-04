import { describe, expect, it } from 'vitest'
import { normalizeVaultPaste } from './pasteHandling'

const VAULT_HEADER = '$ANSIBLE_VAULT;1.1;AES256'
const VAULT_PAYLOAD = `${'a'.repeat(80)}\n${'b'.repeat(64)}`
const RAW_VAULT = `${VAULT_HEADER}\n${VAULT_PAYLOAD}`

function indentVault(value: string, indentation = ' '.repeat(10)): string {
  return value.split('\n').map((line) => `${indentation}${line}`).join('\n')
}

describe('normalizeVaultPaste', () => {
  it('normalizes line endings and outer whitespace for raw Vault text', () => {
    const pasted = `  \r\n${RAW_VAULT.replaceAll('\n', '\r\n')}\r\n  `

    expect(normalizeVaultPaste(pasted)).toBe(RAW_VAULT)
  })

  it('rejects bare carriage-return line endings', () => {
    const pasted = RAW_VAULT.replaceAll('\n', '\r')

    expect(normalizeVaultPaste(pasted)).toBeNull()
    expect(normalizeVaultPaste(`${RAW_VAULT}\r`)).toBeNull()
    expect(normalizeVaultPaste(`\r${RAW_VAULT}`)).toBeNull()
  })

  it('passes through an already normalized raw Vault value', () => {
    expect(normalizeVaultPaste(RAW_VAULT)).toBe(RAW_VAULT)
  })

  it('extracts one indented !vault block without using its YAML key', () => {
    const pasted = [
      'application_secret: !vault |',
      indentVault(RAW_VAULT),
      'other_setting: unchanged',
    ].join('\n')

    expect(normalizeVaultPaste(pasted)).toBe(RAW_VAULT)
  })

  it('extracts a Vault block used as a sequence element', () => {
    const pasted = [
      'secrets:',
      '  - !vault |',
      indentVault(RAW_VAULT, '      '),
    ].join('\n')

    expect(normalizeVaultPaste(pasted)).toBe(RAW_VAULT)
  })

  it('extracts a bare root Vault tag without treating it as a YAML key', () => {
    const pasted = `!vault |\n${indentVault(RAW_VAULT, '  ')}`

    expect(normalizeVaultPaste(pasted)).toBe(RAW_VAULT)
  })

  it('uses the parsed value of literal and folded block scalars', () => {
    const folded = [
      'secret: !vault >-',
      `  ${VAULT_HEADER}`,
      '',
      `  ${'a'.repeat(80)}`,
      '',
      `  ${'b'.repeat(64)}`,
    ].join('\n')
    const ordinaryFolded = `secret: !vault >\n${indentVault(RAW_VAULT, '  ')}`

    expect(normalizeVaultPaste(folded)).toBe(RAW_VAULT)
    expect(normalizeVaultPaste(ordinaryFolded)).toBeNull()
  })

  it('rejects a mapping marker without separation whitespace', () => {
    const pasted = `secret:!vault |\n${indentVault(RAW_VAULT)}`

    expect(normalizeVaultPaste(pasted)).toBeNull()
  })

  it('rejects a tab-indented marker', () => {
    const pasted = `\tsecret: !vault |\n${indentVault(RAW_VAULT)}`

    expect(normalizeVaultPaste(pasted)).toBeNull()
  })

  it('extracts an indented marker while preserving its indentation', () => {
    const pasted = `\n  secret: !vault |\n${indentVault(RAW_VAULT, '    ')}\n`

    expect(normalizeVaultPaste(pasted)).toBe(RAW_VAULT)
  })

  it('rejects a tagged body at the same indentation as its marker', () => {
    const pasted = `\n  secret: !vault |\n${indentVault(RAW_VAULT, '  ')}\n`

    expect(normalizeVaultPaste(pasted)).toBeNull()
  })

  it('extracts an encrypt_string-style block with CRLF line endings', () => {
    const pasted = [
      'the_secret: !vault |- ',
      indentVault(RAW_VAULT, '    '),
    ].join('\r\n')

    expect(normalizeVaultPaste(pasted)).toBe(RAW_VAULT)
  })

  it('extracts numeric indentation indicators and trailing marker comments', () => {
    for (const indicator of ['|2', '|+2', '|-2', '|2+', '|2-']) {
      const pasted = `secret: !vault ${indicator} # encrypted\n${indentVault(RAW_VAULT, '  ')}`

      expect(normalizeVaultPaste(pasted), indicator).toBe(RAW_VAULT)
    }

    const sequenceMapping = `- secret: !vault |2\n${indentVault(RAW_VAULT, '    ')}`
    expect(normalizeVaultPaste(sequenceMapping)).toBe(RAW_VAULT)
  })

  it('rejects invalid indicators and preserves explicit indentation as scalar content', () => {
    for (const indicator of ['|0', '|10', '|22', '|++', '|2+-']) {
      const pasted = `secret: !vault ${indicator}\n${indentVault(RAW_VAULT, '  ')}`

      expect(normalizeVaultPaste(pasted), indicator).toBeNull()
    }

    const underIndented = `secret: !vault |2\n${indentVault(RAW_VAULT, ' ')}`
    const overIndented = `secret: !vault |2\n${indentVault(RAW_VAULT, '    ')}`
    const mixedIndentation = `secret: !vault |2\n${indentVault(RAW_VAULT, '    ')}\n  aaaa`
    expect(normalizeVaultPaste(underIndented)).toBeNull()
    expect(normalizeVaultPaste(overIndented)).toBeNull()
    expect(normalizeVaultPaste(mixedIndentation)).toBeNull()
  })

  it('accepts comment characters in quoted keys but not comments attached to the indicator', () => {
    for (const key of ['"secret # archive"', "'secret # archive'", '"secret: archive"']) {
      const pasted = `${key}: !vault | # encrypted\n${indentVault(RAW_VAULT)}`

      expect(normalizeVaultPaste(pasted), key).toBe(RAW_VAULT)
    }

    expect(normalizeVaultPaste(`secret: !vault |# encrypted\n${indentVault(RAW_VAULT)}`)).toBeNull()
  })

  it('returns null for arbitrary YAML without a recognized Vault block', () => {
    const pasted = 'application:\n  secret: plaintext\n  enabled: true'

    expect(normalizeVaultPaste(pasted)).toBeNull()
  })

  it('rejects mixed prose without quadratic marker scanning', () => {
    const pasted = [
      'word '.repeat(32_000),
      'secret: !vault |',
      indentVault(RAW_VAULT),
    ].join('\n')

    expect(normalizeVaultPaste(pasted)).toBeNull()
  })

  it('handles large mappings without quadratic duplicate-key checks', () => {
    const mapping = Array.from({ length: 32_000 }, (_, index) => `setting_${index}: value`)
    const pasted = [
      ...mapping,
      'secret: !vault |',
      indentVault(RAW_VAULT),
    ].join('\n')

    expect(normalizeVaultPaste(pasted)).toBe(RAW_VAULT)
  })

  it('returns null for a marker nested inside a YAML block scalar', () => {
    for (const scalarMarker of [
      '|',
      '>-',
      '!unsafe |',
      '&memo |',
      '--- !unsafe |',
      'notes: |',
      'notes: !unsafe |',
      'notes: &memo |',
      '"notes # archive": | # documentation',
      "'notes # archive': |",
    ]) {
      const pasted = [
        scalarMarker,
        '  secret: !vault |',
        indentVault(RAW_VAULT, '    '),
      ].join('\n')

      expect(normalizeVaultPaste(pasted), scalarMarker).toBeNull()
    }
  })

  it('returns null for a marker continued from a multiline plain scalar', () => {
    const pasted = [
      'notes: description',
      '  !vault |',
      indentVault(RAW_VAULT, '    '),
    ].join('\n')

    expect(normalizeVaultPaste(pasted)).toBeNull()
  })

  it('returns null for markers inside explicit-key block scalars', () => {
    const rootExplicitKey = [
      '? |',
      '  secret: !vault |',
      indentVault(RAW_VAULT, '    '),
      ': value',
    ].join('\n')
    const sequenceExplicitKey = [
      '- ? |',
      '    secret: !vault |',
      indentVault(RAW_VAULT, '      '),
      '  : value',
    ].join('\n')
    const nestedSequenceExplicitKey = [
      '- - ? |',
      '      secret: !vault |',
      indentVault(RAW_VAULT, '        '),
      '    : value',
    ].join('\n')

    expect(normalizeVaultPaste(rootExplicitKey)).toBeNull()
    expect(normalizeVaultPaste(sequenceExplicitKey)).toBeNull()
    expect(normalizeVaultPaste(nestedSequenceExplicitKey)).toBeNull()
  })

  it('distinguishes a sequence-mapping block scalar from a later sibling marker', () => {
    const nested = [
      '- notes: |',
      '    secret: !vault |',
      indentVault(RAW_VAULT, '      '),
    ].join('\n')
    const sibling = [
      '- notes: |',
      '    documentation',
      '  secret: !vault |',
      indentVault(RAW_VAULT, '    '),
    ].join('\n')

    expect(normalizeVaultPaste(nested)).toBeNull()
    expect(normalizeVaultPaste(sibling)).toBe(RAW_VAULT)
  })

  it('returns null for a marker inside a multiline quoted YAML scalar', () => {
    for (const [opening, closing] of [
      ['notes: "description', '  continued"'],
      ["notes: 'description", "  continued'"],
    ]) {
      const pasted = [
        opening,
        '  secret: !vault |',
        indentVault(RAW_VAULT, '    '),
        closing,
      ].join('\n')

      expect(normalizeVaultPaste(pasted), opening).toBeNull()
    }
  })

  it('returns null when a tagged block is alongside an unsafe-label Vault header', () => {
    const pasted = [
      'secret: !vault |',
      indentVault(RAW_VAULT),
      '$ANSIBLE_VAULT;1.2;AES256;dev\u200b',
      VAULT_PAYLOAD,
    ].join('\n')

    expect(normalizeVaultPaste(pasted)).toBeNull()
  })

  it('accepts safe Vault 1.2 headers and rejects unsafe extracted labels', () => {
    const labeled = `$ANSIBLE_VAULT;1.2;AES256;dev\n${VAULT_PAYLOAD}`
    const unlabeled = `$ANSIBLE_VAULT;1.2;AES256\n${VAULT_PAYLOAD}`
    const unicodeLabel = `$ANSIBLE_VAULT;1.2;AES256;dev-🔐\n${VAULT_PAYLOAD}`
    const invisibleLabel = `$ANSIBLE_VAULT;1.2;AES256;dev\u200b\n${VAULT_PAYLOAD}`
    const oversizedLabel = `$ANSIBLE_VAULT;1.2;AES256;${'x'.repeat(257)}\n${VAULT_PAYLOAD}`
    const unpairedHighSurrogateLabel = `$ANSIBLE_VAULT;1.2;AES256;dev\uD800\n${VAULT_PAYLOAD}`
    const unpairedLowSurrogateLabel = `$ANSIBLE_VAULT;1.2;AES256;dev\uDC00\n${VAULT_PAYLOAD}`

    expect(normalizeVaultPaste(labeled)).toBe(labeled)
    expect(normalizeVaultPaste(unlabeled)).toBe(unlabeled)
    expect(normalizeVaultPaste(unicodeLabel)).toBe(unicodeLabel)
    expect(normalizeVaultPaste(invisibleLabel)).toBeNull()
    expect(normalizeVaultPaste(oversizedLabel)).toBeNull()
    expect(normalizeVaultPaste(unpairedHighSurrogateLabel)).toBeNull()
    expect(normalizeVaultPaste(unpairedLowSurrogateLabel)).toBeNull()
  })

  it('returns null when a tagged block has no Vault header', () => {
    const pasted = [
      'secret: !vault |',
      indentVault('deadbeef'),
    ].join('\n')

    expect(normalizeVaultPaste(pasted)).toBeNull()
  })

  it('returns null for a truncated raw Vault block', () => {
    expect(normalizeVaultPaste(VAULT_HEADER)).toBeNull()
    expect(normalizeVaultPaste(`${VAULT_HEADER}\n${'a'.repeat(79)}`)).toBeNull()
  })

  it('accepts odd-length payload lines when the combined hex body is even', () => {
    const nonHex = `${VAULT_HEADER}\n${'a'.repeat(80)}\nnot-hex`
    const oddLength = `${VAULT_HEADER}\n${'a'.repeat(79)}`
    const rewrapped = `${VAULT_HEADER}\n${'a'.repeat(79)}\nb`
    const tooLong = `${VAULT_HEADER}\n${'c'.repeat(81)}\nd`
    const uppercase = `${VAULT_HEADER}\n${'A'.repeat(80)}`
    const emptyLine = `${VAULT_HEADER}\n${'a'.repeat(40)}\n\n${'b'.repeat(40)}`

    expect(normalizeVaultPaste(nonHex)).toBeNull()
    expect(normalizeVaultPaste(oddLength)).toBeNull()
    expect(normalizeVaultPaste(rewrapped)).toBe(rewrapped)
    expect(normalizeVaultPaste(tooLong)).toBeNull()
    expect(normalizeVaultPaste(uppercase)).toBe(uppercase)
    expect(normalizeVaultPaste(emptyLine)).toBeNull()
  })

  it('returns null for unsupported Vault headers', () => {
    expect(normalizeVaultPaste('$ANSIBLE_VAULT;1.3;AES256\n' + VAULT_PAYLOAD)).toBeNull()
    expect(normalizeVaultPaste('$ANSIBLE_VAULT;1.1;AES128\n' + VAULT_PAYLOAD)).toBeNull()
  })

  it('returns null when the input contains multiple tagged Vault blocks', () => {
    const pasted = [
      'first: !vault |',
      indentVault(RAW_VAULT),
      'second: !vault |',
      indentVault(RAW_VAULT),
    ].join('\n')

    expect(normalizeVaultPaste(pasted)).toBeNull()
  })

  it('rejects duplicate empty mapping keys', () => {
    const pasted = [
      ': first',
      ': second',
      'secret: !vault |',
      indentVault(RAW_VAULT),
    ].join('\n')

    expect(normalizeVaultPaste(pasted)).toBeNull()
  })

  it('rejects parse errors and multi-document YAML', () => {
    const duplicateKey = [
      'secret: !vault |',
      indentVault(RAW_VAULT),
      'secret: duplicate',
    ].join('\n')
    const multipleDocuments = [
      '---',
      'secret: !vault |',
      indentVault(RAW_VAULT),
      '---',
      'other: value',
    ].join('\n')
    const equivalentDuplicateKey = [
      'settings:',
      '  mode: first',
      '  "mode": second',
      'secret: !vault |',
      indentVault(RAW_VAULT),
    ].join('\n')

    expect(normalizeVaultPaste(duplicateKey)).toBeNull()
    expect(normalizeVaultPaste(equivalentDuplicateKey)).toBeNull()
    expect(normalizeVaultPaste(multipleDocuments)).toBeNull()
  })

  it('rejects unsupported tags, aliases, anchors, and tagged mapping keys', () => {
    const unsupportedTag = [
      'other: !unsafe value',
      'secret: !vault |',
      indentVault(RAW_VAULT),
    ].join('\n')
    const standardTag = [
      'other: !!str value',
      'secret: !vault |',
      indentVault(RAW_VAULT),
    ].join('\n')
    const anchored = [
      'secret: &copy !vault |',
      indentVault(RAW_VAULT),
      'copy: *copy',
    ].join('\n')
    const taggedKey = [
      '? !vault |',
      indentVault(RAW_VAULT, '  '),
      ': value',
    ].join('\n')

    expect(normalizeVaultPaste(unsupportedTag)).toBeNull()
    expect(normalizeVaultPaste(standardTag)).toBeNull()
    expect(normalizeVaultPaste(anchored)).toBeNull()
    expect(normalizeVaultPaste(taggedKey)).toBeNull()
  })

  it('rejects Vault tags anywhere inside collection mapping keys', () => {
    const directMappingKey = [
      '? secret: !vault |',
      indentVault(RAW_VAULT, '    '),
      ': value',
    ].join('\n')
    const nestedMappingKey = [
      '? outer:',
      '    inner:',
      '      secret: !vault |',
      indentVault(RAW_VAULT, '        '),
      ': value',
    ].join('\n')
    const nestedSequenceKey = [
      '? - nested:',
      '      secret: !vault |',
      indentVault(RAW_VAULT, '        '),
      ': value',
    ].join('\n')

    expect(normalizeVaultPaste(directMappingKey)).toBeNull()
    expect(normalizeVaultPaste(nestedMappingKey)).toBeNull()
    expect(normalizeVaultPaste(nestedSequenceKey)).toBeNull()
  })

  it('rejects !vault tags on non-block scalars', () => {
    const escapedVault = RAW_VAULT.replaceAll('\n', '\\n')

    expect(normalizeVaultPaste(`secret: !vault "${escapedVault}"`)).toBeNull()
  })

  it('returns null when a tagged block is alongside a raw Vault block', () => {
    const pasted = [
      'secret: !vault |',
      indentVault(RAW_VAULT),
      RAW_VAULT,
    ].join('\n')

    expect(normalizeVaultPaste(pasted)).toBeNull()
  })

  it('returns null when a tagged block is alongside an unsupported or malformed Vault header', () => {
    for (const extraHeader of [
      '$ANSIBLE_VAULT;1.3;AES256',
      '$ANSIBLE_VAULT;1.2;AES128',
      '$ANSIBLE_VAULT;1.2;AES256;',
    ]) {
      const pasted = [
        'secret: !vault |',
        indentVault(RAW_VAULT),
        extraHeader,
        VAULT_PAYLOAD,
      ].join('\n')

      expect(normalizeVaultPaste(pasted), extraHeader).toBeNull()
    }
  })

  it('returns null when one tagged block contains multiple Vault headers', () => {
    const pasted = [
      'secret: !vault |',
      indentVault(`${RAW_VAULT}\n${RAW_VAULT}`),
    ].join('\n')

    expect(normalizeVaultPaste(pasted)).toBeNull()
  })

  it('does not treat a lookalike prose marker as a YAML Vault block', () => {
    const pasted = `this is not a YAML key !vault |\n${indentVault(RAW_VAULT)}`
    const multipleColons = `this is prose: secret: !vault |\n${indentVault(RAW_VAULT)}`

    expect(normalizeVaultPaste(pasted)).toBeNull()
    expect(normalizeVaultPaste(multipleColons)).toBeNull()
  })

  it('does not treat indented or unindented commented-out tags as YAML blocks', () => {
    for (const marker of ['# secret: !vault |', '  # secret: !vault |']) {
      const pasted = `${marker}\n${indentVault(RAW_VAULT)}`

      expect(normalizeVaultPaste(pasted)).toBeNull()
    }
  })

  it('does not treat an inline commented-out tag as a YAML block', () => {
    for (const marker of [
      'placeholder # secret: !vault |',
      'placeholder: "quoted # text" # secret: !vault |',
    ]) {
      const pasted = `${marker}\n${indentVault(RAW_VAULT)}`

      expect(normalizeVaultPaste(pasted), marker).toBeNull()
    }
  })
})
