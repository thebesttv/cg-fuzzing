# cmark-gfm Fuzzing Resources

This directory contains resources for fuzzing cmark-gfm using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (Markdown syntax tokens)
- `in/` - Initial input corpus (Markdown files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on:
- CommonMark specification
- GitHub Flavored Markdown (GFM) extensions
- General Markdown syntax

The initial input corpus contains various Markdown samples covering:
- Headers, emphasis, links, images
- Code blocks (fenced and inline)
- Lists (ordered, unordered, task lists)
- Tables (GFM)
- HTML blocks and inline HTML
- Special characters and escapes

## Usage

Build the fuzzing Docker image:
```bash
docker build -f cmark-gfm/fuzz.dockerfile -t cmark-gfm-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm cmark-gfm-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm cmark-gfm-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: cmark-gfm CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Markdown files parsed by cmark-gfm
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses cmark-gfm version 0.29.0.gfm.13, matching the bc.dockerfile.
