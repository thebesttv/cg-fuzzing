# recode Fuzzing Resources

This directory contains resources for fuzzing recode using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (character set names and encoding syntax)
- `in/` - Initial input corpus (text files with various encodings)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

- dict: Custom dictionary based on recode character set names and syntax
- in/: Sample text files for initial corpus

## Usage

Build the fuzzing Docker image:
```bash
docker build -f recode/fuzz.dockerfile -t recode-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm recode-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm recode-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: recode CLI binary (character set converter)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Text files converted from UTF-8 to Latin-1
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses recode version 3.7.14, matching the bc.dockerfile.
