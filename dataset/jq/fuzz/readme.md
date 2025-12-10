# jq Fuzzing Resources

This directory contains resources for fuzzing jq using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing
- `in/` - Initial input corpus (JSON files)
- `fuzz.sh` - Script to start fuzzing

## External Resources

The dictionary file (`dict`) is based on the jq.dict from Google OSS-Fuzz project:
- Source: https://github.com/google/oss-fuzz/blob/master/projects/jq/jq.dict
- Extended with additional jq keywords and operators

The initial input corpus contains basic JSON samples created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f jq/fuzz.dockerfile -t jq-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm jq-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm -e AFL_PARALLEL=4 jq-fuzz ./fuzz.sh
```

## Fuzzing Strategy

- **Target**: jq CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: JSON data files processed with '.' filter
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses jq version 1.8.1, matching the bc.dockerfile.
