# wren Fuzzing Resources

This directory contains resources for fuzzing the Wren scripting language using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with Wren syntax tokens
- `in/` - Initial input corpus (Wren script files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on Wren language syntax:
- Reference: https://wren.io

The initial input corpus contains basic Wren programs created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f wren/fuzz.dockerfile -t wren-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm wren-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm wren-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: wren_parse harness (interprets Wren script files)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Wren script files (.wren)
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses wren version 0.4.0, matching the bc.dockerfile.
