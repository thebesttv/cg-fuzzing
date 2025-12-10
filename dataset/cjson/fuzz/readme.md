# cJSON Fuzzing Resources

This directory contains resources for fuzzing cJSON using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (from cJSON's fuzzing/json.dict)
- `in/` - Initial input corpus (from cJSON's fuzzing/inputs)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) is sourced directly from cJSON repository:
- https://github.com/DaveGamble/cJSON/blob/v1.7.19/fuzzing/json.dict

The initial input corpus contains sample JSON files from:
- https://github.com/DaveGamble/cJSON/tree/v1.7.19/fuzzing/inputs

## Usage

Build the fuzzing Docker image:
```bash
docker build -f cjson/fuzz.dockerfile -t cjson-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm cjson-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm cjson-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: cjson_afl binary (cJSON's official AFL harness)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: JSON files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses cJSON version 1.7.19, matching the bc.dockerfile.
