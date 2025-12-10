# wdiff Fuzzing Resources

This directory contains resources for fuzzing GNU wdiff using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing
- `in/` - Initial input corpus (unified diff format files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created for this project based on diff syntax and common text patterns.

The initial input corpus contains basic unified diff samples created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f wdiff/fuzz.dockerfile -t wdiff-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm wdiff-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm wdiff-fuzz ./fuzz.sh -j 4
```

Monitor fuzzing progress:
```bash
docker run -it --rm wdiff-fuzz ./whatsup.sh
```

## Fuzzing Strategy

- **Target**: wdiff CLI binary with -d option (reads unified diff from stdin)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Unified diff format text processed with -d option
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses wdiff version 1.2.2, matching the bc.dockerfile.
