# libcue Fuzzing Resources

This directory contains resources for fuzzing libcue's CUE sheet parser using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (CUE format keywords)
- `in/` - Initial input corpus (CUE sheet files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on:
- CUE sheet format specification
- Common CUE sheet keywords and values

The initial input corpus contains minimal and sample CUE files created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f libcue/fuzz.dockerfile -t libcue-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm libcue-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm libcue-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: cue_parse binary (CUE sheet parser harness)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: CUE sheet files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses libcue version 2.3.0, matching the bc.dockerfile.
