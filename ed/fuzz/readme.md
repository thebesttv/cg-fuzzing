# GNU ed Fuzzing Resources

This directory contains resources for fuzzing GNU ed (line editor) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (ed commands)
- `in/` - Initial input corpus (ed script files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) contains ed-specific commands such as:
- Basic commands (p, n, d, a, i, c, s, w, q, etc.)
- Address specifications (., $, +, -, etc.)
- Regular expression patterns for g and s commands

The initial input corpus contains sample ed scripts.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f ed/fuzz.dockerfile -t ed-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm ed-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm ed-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: GNU ed CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: ed script commands read from file with -s option (silent mode)
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses GNU ed version 1.22, matching the bc.dockerfile.
