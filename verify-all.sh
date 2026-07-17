#!/usr/bin/env bash
# Runs every language's known-answer test against spec/vectors.json. Each implementation
# must reproduce those vectors byte for byte. Runtimes you don't have installed fall back
# to the official Docker image automatically.
#
#   ./verify-all.sh            # everything
#   ./verify-all.sh node go    # only these
#
# Needs no .env and no running server — the vectors are a pure offline oracle.
set -uo pipefail

cd "$(dirname "$0")"
ROOT="$PWD"

RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; DIM=$'\033[2m'; RESET=$'\033[0m'

have() { command -v "$1" >/dev/null 2>&1; }
docker_ok() { have docker && docker info >/dev/null 2>&1; }

PASSED=(); FAILED=(); SKIPPED=()

# run <name> <how> <command...>
run_one() {
  local name="$1" how="$2"; shift 2
  printf '%s\n' "${DIM}────────────────────────────────────────${RESET}"
  printf '▶ %-8s %s%s%s\n' "$name" "$DIM" "$how" "$RESET"
  local log; log="$(mktemp)"
  # Take the exit code of the command itself. Piping to tail would report the exit code of
  # tail instead, turning a failing suite into a green run.
  if "$@" >"$log" 2>&1; then
    printf '  %s✓ pass%s\n' "$GREEN" "$RESET"
    grep -vE '^[[:space:]]*$' "$log" | tail -3 | sed 's/^/    /'
    PASSED+=("$name")
  else
    printf '  %s✗ FAIL%s (exit=%d)\n' "$RED" "$RESET" "$?"
    tail -15 "$log" | sed 's/^/    /'
    FAILED+=("$name")
  fi
  rm -f "$log"
}

skip() {
  printf '%s\n' "${DIM}────────────────────────────────────────${RESET}"
  printf '▶ %-8s %sskipped:%s %s\n' "$1" "$YELLOW" "$RESET" "$2"
  SKIPPED+=("$1")
}

want() {
  [ "$#" -eq 0 ] && return 0
  local t
  for t in "${TARGETS[@]}"; do [ "$t" = "$1" ] && return 0; done
  return 1
}

TARGETS=("$@")
sel() { [ "${#TARGETS[@]}" -eq 0 ] || want "$1"; }

# ---- node ----
if sel node; then
  if have node; then run_one node "local node $(node --version)" \
       env -C "$ROOT/node" node --test "test/*.test.js"
  elif docker_ok; then run_one node "docker node:22-slim" \
       docker run --rm -v "$ROOT":/app -w /app/node node:22-slim node --test "test/*.test.js"
  else skip node "no node and no usable docker"; fi
fi

# ---- python ----
if sel python; then
  if have python3; then run_one python "local python3 $(python3 --version 2>&1 | cut -d' ' -f2)" \
       env -C "$ROOT/python" python3 -m unittest discover -s test
  elif docker_ok; then run_one python "docker python:3.12-slim" \
       docker run --rm -v "$ROOT":/app -w /app/python python:3.12-slim python -m unittest discover -s test
  else skip python "no python3 and no usable docker"; fi
fi

# ---- go ----
if sel go; then
  if have go; then run_one go "local $(go version | awk '{print $3}')" \
       env -C "$ROOT/go" go test ./...
  elif docker_ok; then run_one go "docker golang:1.23" \
       docker run --rm -v "$ROOT":/app -w /app/go golang:1.23 go test ./...
  else skip go "no go and no usable docker"; fi
fi

# ---- ruby ----
if sel ruby; then
  if have ruby; then run_one ruby "local ruby $(ruby --version | cut -d' ' -f2)" \
       env -C "$ROOT/ruby" ruby test/vectors_test.rb
  elif docker_ok; then run_one ruby "docker ruby:3.3-slim" \
       docker run --rm -v "$ROOT":/app -w /app/ruby ruby:3.3-slim ruby test/vectors_test.rb
  else skip ruby "no ruby and no usable docker"; fi
fi

# ---- php ----
if sel php; then
  if have php; then run_one php "local php $(php -r 'echo PHP_VERSION;')" \
       env -C "$ROOT/php" php test/vectors_test.php
  elif docker_ok; then run_one php "docker php:8.3-cli" \
       docker run --rm -v "$ROOT":/app -w /app/php php:8.3-cli php test/vectors_test.php
  else skip php "no php and no usable docker"; fi
fi

# ---- java ----
if sel java; then
  if have mvn; then run_one java "local maven" \
       mvn -f "$ROOT/java/pom.xml" -q test
  elif docker_ok; then run_one java "docker maven:3.9-eclipse-temurin-17" \
       docker run --rm -v "$ROOT":/app -w /app/java maven:3.9-eclipse-temurin-17 mvn -q test
  else skip java "no maven and no usable docker"; fi
fi

# ---- dotnet ----
if sel dotnet; then
  if have dotnet; then run_one dotnet "local dotnet $(dotnet --version 2>/dev/null)" \
       dotnet test "$ROOT/dotnet" --nologo -v q
  elif docker_ok; then run_one dotnet "docker mcr.microsoft.com/dotnet/sdk:8.0" \
       docker run --rm -v "$ROOT":/app -w /app/dotnet mcr.microsoft.com/dotnet/sdk:8.0 dotnet test --nologo -v q
  else skip dotnet "no dotnet and no usable docker"; fi
fi

# ---- rust ----
if sel rust; then
  if have cargo; then run_one rust "local $(cargo --version | awk '{print $1" "$2}')" \
       env -C "$ROOT/rust" cargo test -q
  elif docker_ok; then run_one rust "docker rust:1-slim" \
       docker run --rm -v "$ROOT":/app -w /app/rust rust:1-slim cargo test -q
  else skip rust "no cargo and no usable docker"; fi
fi

echo
printf '%s\n' "${DIM}════════════════════════════════════════${RESET}"
printf 'passed %s%d%s' "$GREEN" "${#PASSED[@]}" "$RESET"
[ "${#FAILED[@]}" -gt 0 ]  && printf '   failed %s%d%s (%s)' "$RED" "${#FAILED[@]}" "$RESET" "${FAILED[*]}"
[ "${#SKIPPED[@]}" -gt 0 ] && printf '   skipped %s%d%s (%s)' "$YELLOW" "${#SKIPPED[@]}" "$RESET" "${SKIPPED[*]}"
echo
[ "${#FAILED[@]}" -eq 0 ] || exit 1
