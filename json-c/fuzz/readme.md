# json-c Fuzzing Resources

This directory contains resources for fuzzing json-c using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing
- `in/` - Initial input corpus (JSON files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) is based on the json-c project's own fuzzing dictionary:
- Source: https://github.com/json-c/json-c/tree/master/fuzz

The initial input corpus contains basic JSON samples created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f json-c/fuzz.dockerfile -t json-c-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm json-c-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm json-c-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: json_parse CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: JSON data files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses json-c version 0.18-20240915, matching the bc.dockerfile.
