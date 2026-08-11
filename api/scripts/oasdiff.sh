#!/usr/bin/env bash
set -euo pipefail

ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)"
VERSION="1.28.0"
CACHE_ROOT="${OASDIFF_CACHE_DIR:-$ROOT/.tmp/oasdiff}"
BASE_URL="https://github.com/oasdiff/oasdiff/releases/download/v${VERSION}"
CONNECT_TIMEOUT_SECONDS=10
TRANSFER_TIMEOUT_SECONDS=120
RETRIES=2

fail() {
  printf 'oasdiff launcher failed: %s\n' "$1" >&2
  exit 1
}

case "$(uname -s):$(uname -m)" in
  Darwin:arm64|Darwin:x86_64)
    ARCHIVE="oasdiff_${VERSION}_darwin_all.tar.gz"
    EXPECTED_SHA256="ff76474bf47bfb806d1711aa3e962b8e55570badcd462fa487b80aa532a823db"
    # The v1.28.0 release asset is 12,478,394 bytes. A 16 MiB cap leaves
    # reviewed headroom while preventing an unexpected response from filling disk.
    MAX_ARCHIVE_BYTES=16777216
    ;;
  Linux:x86_64|Linux:amd64)
    ARCHIVE="oasdiff_${VERSION}_linux_amd64.tar.gz"
    EXPECTED_SHA256="e0ef076f2cf953d922addc04be9c3851cf3ec18f7678d2b94d44cea23dca51b5"
    # The v1.28.0 release asset is 6,361,417 bytes.
    MAX_ARCHIVE_BYTES=8388608
    ;;
  Linux:aarch64|Linux:arm64)
    ARCHIVE="oasdiff_${VERSION}_linux_arm64.tar.gz"
    EXPECTED_SHA256="cb15a381472321ac602cc252e65018d03feba7e6449a0854e1181680444d4051"
    # The v1.28.0 release asset is 5,766,429 bytes.
    MAX_ARCHIVE_BYTES=8388608
    ;;
  *)
    fail "unsupported host $(uname -s)/$(uname -m); supported hosts are Darwin arm64/x86_64 and Linux arm64/x86_64"
    ;;
esac

command -v curl >/dev/null 2>&1 || fail 'curl is required'
command -v tar >/dev/null 2>&1 || fail 'tar is required'

sha256() {
  local file="$1"
  local digest
  if command -v sha256sum >/dev/null 2>&1; then
    read -r digest _ < <(sha256sum "$file")
  elif command -v shasum >/dev/null 2>&1; then
    read -r digest _ < <(shasum -a 256 "$file")
  else
    fail 'sha256sum or shasum is required to verify the pinned archive'
  fi
  printf '%s' "$digest"
}

file_size_bytes() {
  local file="$1"
  local bytes
  bytes="$(wc -c < "$file")" || fail "cannot measure archive size for $file"
  bytes="${bytes//[[:space:]]/}"
  [[ "$bytes" =~ ^[0-9]+$ ]] || fail "invalid archive size for $file: $bytes"
  printf '%s' "$bytes"
}

check_archive_size() {
  local file="$1"
  local description="$2"
  local observed_bytes
  observed_bytes="$(file_size_bytes "$file")"
  if (( observed_bytes > MAX_ARCHIVE_BYTES )); then
    fail "$description exceeds archive byte budget: configured max $MAX_ARCHIVE_BYTES, observed $observed_bytes; remove the cache file and update the reviewed cap and checksum only if the upstream release asset changed"
  fi
}

mkdir -p "$CACHE_ROOT"
ARCHIVE_PATH="$CACHE_ROOT/$ARCHIVE"
PART_PATH="$ARCHIVE_PATH.part.$$"
TMP_DIR="$(mktemp -d)"
cleanup() {
  if [[ -e "$PART_PATH" ]]; then
    if command -v trash >/dev/null 2>&1; then
      trash "$PART_PATH"
    else
      rm -f "$PART_PATH"
    fi
  fi
  if [[ -d "$TMP_DIR" ]]; then
    if command -v trash >/dev/null 2>&1; then
      trash "$TMP_DIR"
    else
      rm -rf "$TMP_DIR"
    fi
  fi
}
trap cleanup EXIT

if [[ ! -f "$ARCHIVE_PATH" ]]; then
  # A 120-second transfer budget permits about 100 KiB/s for the largest
  # supported archive while bounding a stalled CI job. Two retries make three
  # attempts; each connection must start within 10 seconds.
  if ! curl -fsSL \
    --proto '=https' \
    --tlsv1.2 \
    --connect-timeout "$CONNECT_TIMEOUT_SECONDS" \
    --max-time "$TRANSFER_TIMEOUT_SECONDS" \
    --max-filesize "$MAX_ARCHIVE_BYTES" \
    --retry "$RETRIES" \
    --retry-all-errors \
    --retry-delay 2 \
    "$BASE_URL/$ARCHIVE" \
    -o "$PART_PATH"; then
    PARTIAL_BYTES=0
    if [[ -f "$PART_PATH" ]]; then
      PARTIAL_BYTES="$(file_size_bytes "$PART_PATH")"
    fi
    fail "download failed within archive byte budget: configured max $MAX_ARCHIVE_BYTES, observed partial $PARTIAL_BYTES; retry after network recovery or review a changed upstream release asset"
  fi
  check_archive_size "$PART_PATH" "downloaded $ARCHIVE"
  ACTUAL_SHA256="$(sha256 "$PART_PATH")"
  if [[ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]]; then
    fail "checksum mismatch for downloaded $ARCHIVE: expected $EXPECTED_SHA256, observed $ACTUAL_SHA256"
  fi
  mv "$PART_PATH" "$ARCHIVE_PATH"
fi

check_archive_size "$ARCHIVE_PATH" "cached $ARCHIVE_PATH"
ACTUAL_SHA256="$(sha256 "$ARCHIVE_PATH")"
if [[ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]]; then
  fail "checksum mismatch for cached $ARCHIVE_PATH: expected $EXPECTED_SHA256, observed $ACTUAL_SHA256; remove the cache file and retry"
fi

tar -xzf "$ARCHIVE_PATH" -C "$TMP_DIR"
[[ -x "$TMP_DIR/oasdiff" ]] || fail "verified archive did not contain an executable named oasdiff"
"$TMP_DIR/oasdiff" "$@"
