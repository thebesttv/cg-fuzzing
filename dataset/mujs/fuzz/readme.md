# mujs Fuzzing Resources

This directory contains resources for fuzzing mujs using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (JavaScript keywords and syntax)
- `in/` - Initial input corpus (JavaScript files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on ECMAScript/JavaScript syntax.

The initial input corpus contains basic JavaScript samples created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f mujs/fuzz.dockerfile -t mujs-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm mujs-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm mujs-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: mujs CLI interpreter (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: JavaScript script files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses mujs version 1.3.8, matching the bc.dockerfile.
