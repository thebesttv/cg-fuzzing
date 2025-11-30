# fribidi Fuzzing Resources

This directory contains resources for fuzzing fribidi using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (Unicode bidi control characters)
- `in/` - Initial input corpus (text files with mixed direction text)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

- dict: Custom dictionary based on Unicode bidirectional control characters
- in/: Sample text files with RTL and LTR mixed content

## Usage

Build the fuzzing Docker image:
```bash
docker build -f fribidi/fuzz.dockerfile -t fribidi-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm fribidi-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm fribidi-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: fribidi CLI binary (Unicode bidirectional text tool)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Text files with bidirectional text content
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses fribidi version 1.0.15, matching the bc.dockerfile.
