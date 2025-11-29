# which Fuzzing Resources

This directory contains resources for fuzzing GNU which using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (command names)
- `in/` - Initial input corpus
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file and input corpus are created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f which/fuzz.dockerfile -t which-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm which-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm which-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: GNU which CLI binary
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Command name strings via stdin
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses GNU which version 2.23, matching the bc.dockerfile.
