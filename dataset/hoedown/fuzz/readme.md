# hoedown Fuzzing Resources

This directory contains resources for fuzzing hoedown using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (Markdown syntax elements)
- `in/` - Initial input corpus (Markdown files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

- dict: Custom dictionary based on Markdown syntax
- in/: Sample Markdown files for initial corpus

## Usage

Build the fuzzing Docker image:
```bash
docker build -f hoedown/fuzz.dockerfile -t hoedown-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm hoedown-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm hoedown-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: hoedown CLI binary (Markdown to HTML converter)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Markdown files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses hoedown version 3.0.7, matching the bc.dockerfile.
