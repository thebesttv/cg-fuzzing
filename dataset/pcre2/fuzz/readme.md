# pcre2 Fuzzing Resources

This directory contains resources for fuzzing pcre2 using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (regex syntax patterns)
- `in/` - Initial input corpus (regex patterns)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) is created based on PCRE2 regex syntax:
- Metacharacters and quantifiers
- Character classes
- Named groups and backreferences
- Unicode properties

The initial input corpus contains common regex patterns.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f pcre2/fuzz.dockerfile -t pcre2-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm pcre2-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm pcre2-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: pcre2grep CLI binary (reads regex pattern from file with -f flag)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Regex pattern files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses pcre2 version 10.47, matching the bc.dockerfile.
