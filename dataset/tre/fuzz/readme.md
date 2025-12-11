# TRE Fuzzing Resources

This directory contains resources for fuzzing TRE's agrep tool using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (regex patterns)
- `in/` - Initial input corpus (text files to search)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) is created based on regular expression syntax and TRE-specific approximate matching patterns.

The initial input corpus contains basic text files for agrep to search.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f tre/fuzz.dockerfile -t tre-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm tre-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm tre-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: agrep CLI binary (approximate grep from TRE library)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Text files to search with regex patterns
- **Static linking**: For better performance and reproducibility

## About TRE

TRE is a lightweight, robust, and efficient POSIX compliant regexp matching library with support for approximate (fuzzy) matching.

## Version

This fuzzing setup uses TRE version 0.9.0, matching the bc.dockerfile.
