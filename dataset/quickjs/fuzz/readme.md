# QuickJS Fuzzing Resources

This directory contains resources for fuzzing QuickJS using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with JavaScript keywords
- `in/` - Initial input corpus (JavaScript files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

Dictionary keywords based on JavaScript/ECMAScript specification.

The initial input corpus contains example JavaScript files created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f quickjs/fuzz.dockerfile -t quickjs-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm quickjs-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm quickjs-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: qjs CLI binary (QuickJS JavaScript interpreter)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: JavaScript source files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses QuickJS version 2024-01-13, matching the bc.dockerfile.
