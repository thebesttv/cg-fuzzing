# time Fuzzing Resources

This directory contains resources for fuzzing GNU time using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing
- `in/` - Initial input corpus
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file and input corpus are created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f time/fuzz.dockerfile -t time-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm time-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm time-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: GNU time CLI binary
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Format string via file input
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses GNU time version 1.9, matching the bc.dockerfile.
