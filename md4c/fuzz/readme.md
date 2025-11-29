# md4c Fuzzing Resources

This directory contains resources for fuzzing md4c (Markdown parser) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (Markdown syntax)
- `in/` - Initial input corpus (Markdown files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) is based on common Markdown syntax elements.

The initial input corpus contains basic Markdown samples created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f md4c/fuzz.dockerfile -t md4c-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm md4c-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm md4c-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: md2html CLI binary (Markdown to HTML converter)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Markdown files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses md4c version release-0.5.2, matching the bc.dockerfile.
