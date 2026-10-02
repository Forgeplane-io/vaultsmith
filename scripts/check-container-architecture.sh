#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo 'usage: bash scripts/check-container-architecture.sh IMAGE amd64|arm64' >&2
  exit 2
fi
image="$1"
arch="$2"
case "$arch" in
  amd64) machine='x86-64' ;;
  arm64) machine='ARM aarch64' ;;
  *) printf 'unsupported executable architecture: %s\n' "$arch" >&2; exit 2 ;;
esac

tmp_dir="$(mktemp -d)"
container=""
cleanup() {
  local rc=0
  if [[ -n "$container" ]]; then
    docker rm "$container" >/dev/null || rc=$?
  fi
  rm -rf "$tmp_dir" || rc=$?
  return "$rc"
}
trap cleanup EXIT

docker image inspect "$image" --format 'image={{.Id}} platform={{.Os}}/{{.Architecture}} user={{.Config.User}} version={{index .Config.Labels "org.opencontainers.image.version"}} revision={{index .Config.Labels "org.opencontainers.image.revision"}} created={{index .Config.Labels "org.opencontainers.image.created"}}'
platform="$(docker image inspect "$image" --format '{{.Os}}/{{.Architecture}}')"
if [[ "$platform" != "linux/$arch" ]]; then
  printf 'image platform mismatch: expected=linux/%s observed=%s\n' "$arch" "$platform" >&2
  exit 1
fi

container="$(docker create --platform "linux/$arch" "$image")"
docker cp "$container:/vaultsmith" "$tmp_dir/vaultsmith"
executable="$(file -b "$tmp_dir/vaultsmith")"
printf 'executable=%s\n' "$executable"
if [[ "$executable" != "ELF 64-bit LSB executable, $machine,"* ]]; then
  printf 'executable architecture mismatch: expected=%s observed=%s\n' "$machine" "$executable" >&2
  exit 1
fi

# Execution may be emulated; it is not a substitute for inspecting the ELF.
docker run --rm --network none --platform "linux/$arch" "$image" -version
