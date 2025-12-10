# mJS Fuzzing Resources

This directory contains resources for fuzzing mJS (Embedded JavaScript engine by Cesanta) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with JavaScript keywords
- `in/` - Initial input corpus (JavaScript files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) contains JavaScript language keywords and operators
commonly used in JavaScript code.

The initial input corpus contains basic JavaScript scripts created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f mjs/fuzz.dockerfile -t mjs-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm mjs-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm mjs-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: mJS CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: JavaScript files executed with `-f` flag
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses mJS version 2.20.0, matching the bc.dockerfile.
