# pv (Pipe Viewer) Fuzzing Resources

This directory contains resources for fuzzing pv (Pipe Viewer) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (pv command line options)
- `in/` - Initial input corpus (command line argument combinations)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created for this project based on:
- pv command line options (-p, -t, -e, -r, etc.)
- Long options (--progress, --timer, etc.)
- Format specifiers (%p, %t, %e, etc.)
- Size suffixes (k, K, m, M, g, G)

The initial input corpus contains:
- `progress.txt` - Simple progress flag
- `combo.txt` - Common flag combination
- `ratelimit.txt` - Rate limiting options
- `named.txt` - Named transfer with force
- `format.txt` - Custom format string

## Usage

Build the fuzzing Docker image:
```bash
docker build -f pv/fuzz.dockerfile -t pv-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm pv-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm pv-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: pv binary (Pipe Viewer)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Command line argument combinations via stdin
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses pv version 1.9.7, matching the bc.dockerfile.
