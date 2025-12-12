#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<EOF
Usage: $0 ./path/to/binary [args...]

Runs an LLVM-instrumented binary and produces coverage files:
  .profraw  - raw profile data
  .profdata - merged profile data (created by llvm-profdata)
  .json     - coverage exported by llvm-cov (JSON). By default the JSON will be
              reformatted via 'jq' (jq is required by default) unless you pass
              --no-reformat to keep the raw output.

You can specify the output JSON filename with -o. If not provided the
script will write to 'default.json'.

Example:
  $0 ./myprog arg1 arg2

Requirements: llvm-profdata, llvm-cov available in PATH and the binary must be compiled
with -fprofile-instr-generate -fcoverage-mapping
Options:
  --no-reformat    Do not run 'jq' to reformat the generated JSON (useful if jq is not available)
  -o <file>        Specify output JSON filename (default: default.json)
EOF
}

NO_REFORMAT=0
OUTPUT_JSON=

# Accept short (-o) and long options. Stop at first non - prefixed arg (the binary).
while [[ ${1:-} == -* ]]; do
  case "$1" in
    --no-reformat)
      NO_REFORMAT=1
      shift
      ;;
    -o)
      if [[ -z ${2:-} ]]; then
        echo "Error: missing argument for -o" >&2
        usage
        exit 2
      fi
      OUTPUT_JSON="$2"
      shift 2
      ;;
    -o?*)
      # Support -oFILE form
      OUTPUT_JSON="${1#-o}"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Error: unknown option '$1'" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
  usage
  exit 0
fi

if [[ $# -lt 1 ]]; then
  echo "Error: missing binary path" >&2
  usage
  exit 2
fi

binary=$1
shift || true

if [[ ! -x "$binary" ]]; then
  echo "Error: binary '$binary' not found or not executable" >&2
  exit 3
fi

command -v llvm-profdata >/dev/null 2>&1 || { echo "Error: llvm-profdata not found in PATH" >&2; exit 4; }
command -v llvm-cov >/dev/null 2>&1 || { echo "Error: llvm-cov not found in PATH" >&2; exit 4; }

# Use OUTPUT_JSON (without the .json suffix) as the prefix for intermediate
# files (.profraw/.profdata). If -o wasn't provided, use the prefix 'default'.
if [[ -n "${OUTPUT_JSON:-}" ]]; then
  prefix="${OUTPUT_JSON%.json}"
  json="$OUTPUT_JSON"
else
  prefix="default"
  json="${prefix}.json"
fi

# Intermediate files are the prefix with .profraw/.profdata suffixes
profraw="${prefix}.profraw"
profdata="${prefix}.profdata"

echo "Running $binary $*"

# Remove any previous profraw and profdata to avoid accidental merging of old data
if [[ -e $profraw ]]; then
  echo "Removing existing $profraw"
  rm -f "$profraw"
fi
if [[ -e $profdata ]]; then
  echo "Removing existing $profdata"
  rm -f "$profdata"
fi

# Ensure we create the requested profraw filename
export LLVM_PROFILE_FILE="$profraw"

set +e
"$binary" "$@"
rc=$?
set -e

if [[ ! -e "$profraw" ]]; then
  echo "Warning: profile data '$profraw' was not created by the run." >&2
  # proceed only if user wants - still attempt to create an empty profdata so llvm-cov errors nicely
fi

echo "Merging profile data into $profdata"
llvm-profdata merge -sparse "$profraw" -o "$profdata" || {
  echo "Error: llvm-profdata merge failed" >&2
  exit 5
}

# If merge succeeded, remove the original raw profile to save space.
if [[ -e "$profraw" ]]; then
  echo "Removing intermediate profile data $profraw"
  rm -f "$profraw"
fi

echo "Exporting coverage to $json"

# If reformatting is requested, stream llvm-cov output directly into jq and
# write the final JSON file. This avoids creating a temporary file when we
# already need jq. With `set -o pipefail` a failure in either llvm-cov or jq
# will cause the pipeline to fail and we handle that case below.
if [[ $NO_REFORMAT -eq 0 ]]; then
  echo "Running llvm-cov and piping to jq to reformat"
  if llvm-cov export "$binary" -instr-profile="$profdata" -format=text | jq -S . > "$json" 2>/dev/null; then
    :
  else
    echo "Error: llvm-cov export or jq failed; try --no-reformat to skip reformatting" >&2
    rm -f "$json" || true
    exit 6
  fi
else
  # When not reformatting, write the raw JSON to a temporary file then move it
  # into place. This preserves the original behavior for --no-reformat.
  tmpjson=$(mktemp "${json}.XXXXXXXX")
  if ! llvm-cov export "$binary" -instr-profile="$profdata" -format=text > "$tmpjson"; then
    echo "Error: llvm-cov export failed" >&2
    rm -f "$tmpjson"
    exit 6
  fi
  mv "$tmpjson" "$json"
fi

# If export succeeded, remove the merged profile data - it's an intermediate artifact.
if [[ -e "$profdata" ]]; then
  echo "Removing intermediate profile data $profdata"
  rm -f "$profdata"
fi

echo "Done. Generated: $json"
exit $rc
