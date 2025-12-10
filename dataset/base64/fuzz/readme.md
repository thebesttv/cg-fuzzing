# base64 Fuzzing Resources

This directory contains resources for fuzzing base64 (encoding library) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (base64 alphabet)
- `in/` - Initial input corpus (base64 encoded files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) contains base64 alphabet characters.

The initial input corpus contains base64-encoded test data created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f base64/fuzz.dockerfile -t base64-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm base64-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm base64-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: base64 CLI binary (base64 encoder/decoder)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Base64 encoded files (fuzzing decode mode with -d)
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses base64 version 0.5.2, matching the bc.dockerfile.
