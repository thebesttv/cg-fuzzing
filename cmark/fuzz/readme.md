# cmark Fuzzing Resources

This directory contains resources for fuzzing cmark (CommonMark Markdown parser) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with Markdown syntax tokens
- `in/` - Initial input corpus (Markdown files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on CommonMark specification:
- Reference: https://spec.commonmark.org/

The initial input corpus contains basic Markdown samples created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f cmark/fuzz.dockerfile -t cmark-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm cmark-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm cmark-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: cmark CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Markdown files processed by cmark
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses cmark version 0.31.1, matching the bc.dockerfile.
