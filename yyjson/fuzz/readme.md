# yyjson Fuzzing Resources

This directory contains resources for fuzzing yyjson using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with JSON-specific tokens
- `in/` - Initial input corpus (JSON files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on JSON syntax (RFC 8259).

The initial input corpus contains basic JSON samples created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f yyjson/fuzz.dockerfile -t yyjson-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm yyjson-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm yyjson-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: yyjson_parse harness binary (parses JSON files using yyjson library)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: JSON data files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses yyjson version 0.12.0, matching the bc.dockerfile.
