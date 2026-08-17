import {
  isAlias,
  isMap,
  isPair,
  isScalar,
  isSeq,
  parseDocument,
  Scalar,
  type Document,
  type Pair,
  type ParsedNode,
} from 'yaml'
import * as z from 'zod/mini'
import { inspectVaultFormat } from './vaultFormat'

const VAULT_HEADER_PREFIX = '$ANSIBLE_VAULT'
const VAULT_TAG = '!vault'
const HEX_PAYLOAD_LINE_PATTERN = /^[0-9a-f]+$/iu
const MAX_VAULT_PAYLOAD_LINE_LENGTH = 80
const UNSAFE_HEADER_ISSUES = new Set(['label-too-long', 'label-unavailable'])
const vaultScalarValueSchema = z.string()
const scalarKeySchema = z.union([z.string(), z.null()])

type ParsedVaultScalar = {
  value: string
  range: [number, number, number]
}

type YamlInspection = {
  candidate: ParsedVaultScalar | null
  invalid: boolean
}

type ParsedYamlPair = Pair<ParsedNode | null, ParsedNode | null>
type TraversedYamlNode = ParsedNode | ParsedYamlPair | null

/**
 * Normalizes a paste only when it is either a complete supported Vault value
 * or one narrowly recognized YAML `!vault` block scalar. A null result means
 * that the caller should preserve the original paste unchanged.
 *
 * YAML is parsed only into an AST. Custom tag resolution is disabled, aliases
 * and anchors are rejected, and the AST is never converted to JavaScript.
 */
export function normalizeVaultPaste(value: string): string | null {
  if (hasUnpairedSurrogate(value)) return null

  const lineEndingNormalized = normalizeLineEndings(value)
  if (lineEndingNormalized.includes('\r')) return null

  const rawCandidate = lineEndingNormalized.trim()
  if (!rawCandidate) return null

  if (isRecognizedVaultText(rawCandidate)) return rawCandidate

  const taggedCandidate = trimOuterBlankLines(lineEndingNormalized)
  const scalar = parseSingleVaultScalar(taggedCandidate)
  if (scalar === null) return null

  const extracted = trimOuterBlankLines(scalar.value)
  if (!isRecognizedVaultText(extracted)) return null
  return hasStandaloneVaultHeader(taggedCandidate, scalar.range) ? null : extracted
}

function hasUnpairedSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index)
    if (codeUnit >= 0xD800 && codeUnit <= 0xDBFF) {
      const nextCodeUnit = value.charCodeAt(index + 1)
      if (!(nextCodeUnit >= 0xDC00 && nextCodeUnit <= 0xDFFF)) return true
      index += 1
    } else if (codeUnit >= 0xDC00 && codeUnit <= 0xDFFF) {
      return true
    }
  }

  return false
}

function normalizeLineEndings(value: string): string {
  return value.replace(/\r\n/gu, '\n')
}

function trimOuterBlankLines(value: string): string {
  const lines = value.split('\n')
  let first = 0
  let last = lines.length

  while (first < last && lines[first].trim() === '') first += 1
  while (last > first && lines[last - 1].trim() === '') last -= 1

  return lines.slice(first, last).join('\n')
}

function parseSingleVaultScalar(value: string): ParsedVaultScalar | null {
  let document: Document.Parsed<ParsedNode>
  try {
    document = parseDocument(value, {
      customTags: [],
      merge: false,
      prettyErrors: false,
      resolveKnownTags: false,
      schema: 'failsafe',
      strict: true,
      // The parser's duplicate-key check scans all preceding map entries. Do
      // the equivalent scalar-key check during the iterative AST walk instead.
      uniqueKeys: false,
      version: '1.2',
    })
  } catch {
    return null
  }

  if (document.errors.length !== 0 || document.warnings.length !== 1) return null

  const [warning] = document.warnings
  if (
    warning.code !== 'TAG_RESOLVE_FAILED'
    || value.slice(warning.pos[0], warning.pos[1]) !== VAULT_TAG
  ) return null

  const inspection: YamlInspection = { candidate: null, invalid: false }
  inspectYamlNodes(document.contents, inspection)
  return inspection.invalid ? null : inspection.candidate
}

function inspectYamlNodes(root: ParsedNode | null, inspection: YamlInspection): void {
  const pending: Array<{ node: TraversedYamlNode, vaultScalarAllowed: boolean }> = [
    { node: root, vaultScalarAllowed: true },
  ]

  while (pending.length > 0) {
    const { node, vaultScalarAllowed } = pending.pop()!
    if (node === null || node === undefined) continue

    if (isPair<ParsedNode | null, ParsedNode | null>(node)) {
      pending.push(
        { node: node.value, vaultScalarAllowed },
        { node: node.key, vaultScalarAllowed: false },
      )
      continue
    }

    if (isAlias(node)) {
      inspection.invalid = true
      continue
    }

    if (!isScalar(node) && !isMap(node) && !isSeq(node)) continue
    if ('anchor' in node && node.anchor !== undefined) inspection.invalid = true

    if (node.tag !== undefined) {
      if (
        node.tag !== VAULT_TAG
        || !vaultScalarAllowed
        || !isScalar(node)
        || (node.type !== Scalar.BLOCK_LITERAL && node.type !== Scalar.BLOCK_FOLDED)
        || node.range === undefined
        || node.range === null
        || inspection.candidate !== null
      ) {
        inspection.invalid = true
      } else {
        const scalarValue = vaultScalarValueSchema.safeParse(node.value)
        if (!scalarValue.success) {
          inspection.invalid = true
        } else {
          inspection.candidate = {
            value: scalarValue.data,
            range: [...node.range],
          }
        }
      }
    }

    if (isMap<ParsedNode | null, ParsedNode | null>(node) && hasDuplicateScalarKeys(node.items)) {
      inspection.invalid = true
    }

    if (isMap<ParsedNode | null, ParsedNode | null>(node) || isSeq<ParsedYamlPair | ParsedNode>(node)) {
      for (let index = node.items.length - 1; index >= 0; index -= 1) {
        pending.push({ node: node.items[index], vaultScalarAllowed })
      }
    }
  }
}

function hasDuplicateScalarKeys(items: readonly ParsedYamlPair[]): boolean {
  const keys = new Set<string | null>()

  for (const item of items) {
    let key: string | null
    if (item.key === null) {
      key = null
    } else if (isScalar(item.key)) {
      const parsedKey = scalarKeySchema.safeParse(item.key.value)
      if (!parsedKey.success) continue
      key = parsedKey.data
    } else {
      continue
    }

    if (keys.has(key)) return true
    keys.add(key)
  }

  return false
}

function hasStandaloneVaultHeader(value: string, scalarRange: ParsedVaultScalar['range']): boolean {
  let lineStart = 0

  while (lineStart <= value.length) {
    const newlineIndex = value.indexOf('\n', lineStart)
    const lineEnd = newlineIndex === -1 ? value.length : newlineIndex
    const line = value.slice(lineStart, lineEnd)

    if (isVaultHeaderLikeLine(line)) {
      const headerOffset = lineStart + line.length - line.trimStart().length
      if (headerOffset < scalarRange[0] || headerOffset >= scalarRange[2]) return true
    }

    if (newlineIndex === -1) return false
    lineStart = newlineIndex + 1
  }

  return false
}

function isVaultHeaderLikeLine(line: string): boolean {
  const candidate = line.trim()
  if (!candidate) return false

  if (inspectVaultFormat(`${candidate}\n00`).status === 'recognized') return true
  return candidate === VAULT_HEADER_PREFIX || candidate.startsWith(`${VAULT_HEADER_PREFIX};`)
}

function isRecognizedVaultText(value: string): boolean {
  const lines = value.split('\n')
  if (lines.length < 2) return false

  const inspection = inspectVaultFormat(value)
  if (inspection.status !== 'recognized') return false
  if (inspection.issues.some((issue) => UNSAFE_HEADER_ISSUES.has(issue))) return false

  let payloadLength = 0
  for (let index = 1; index < lines.length; index += 1) {
    if (!isHexPayloadLine(lines[index])) return false
    payloadLength += lines[index].length
  }
  return payloadLength % 2 === 0
}

function isHexPayloadLine(line: string): boolean {
  return line.length > 0
    && line.length <= MAX_VAULT_PAYLOAD_LINE_LENGTH
    && HEX_PAYLOAD_LINE_PATTERN.test(line)
}
