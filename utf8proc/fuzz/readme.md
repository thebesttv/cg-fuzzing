# utf8proc Fuzzing Resources

This directory contains resources for fuzzing utf8proc (Unicode processing library) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (UTF-8 byte sequences)
- `in/` - Initial input corpus (UTF-8 text files with null terminators)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The fuzzer implementation is based on utf8proc's official fuzzer from the test directory:
- Source: https://github.com/JuliaStrings/utf8proc/blob/master/test/fuzzer.c

The dictionary file contains common UTF-8 byte sequences and edge cases.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f utf8proc/fuzz.dockerfile -t utf8proc-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm utf8proc-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm utf8proc-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: utf8proc_fuzz binary (exercises UTF-8 normalization, case conversion, grapheme breaking)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: UTF-8 encoded text files (null-terminated for fuzzer.c compatibility)
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses utf8proc version 2.11.2, matching the bc.dockerfile.
