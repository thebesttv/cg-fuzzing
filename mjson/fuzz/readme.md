# mjson Fuzzing Resources

This directory contains resources for fuzzing mjson (a small JSON parser) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (JSON tokens and JSONPath expressions)
- `in/` - Initial input corpus (JSON files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file contains common JSON tokens and mjson JSONPath expressions.

The initial input corpus contains sample JSON data created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f mjson/fuzz.dockerfile -t mjson-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm mjson-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm mjson-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: mjson_fuzz binary (exercises JSON parsing, value extraction, and path querying)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: JSON data files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses mjson version 1.2.7, matching the bc.dockerfile.
