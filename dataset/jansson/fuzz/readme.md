# jansson Fuzzing Resources

This directory contains resources for fuzzing jansson using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (JSON syntax tokens)
- `in/` - Initial input corpus (JSON files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) is created based on JSON specification (RFC 8259):
- Structural tokens
- Literals (true, false, null)
- String escape sequences
- Number formats

The initial input corpus contains sample JSON documents.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f jansson/fuzz.dockerfile -t jansson-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm jansson-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm jansson-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: json_process CLI binary (parses JSON and outputs it)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: JSON files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses jansson version 2.14.1, matching the bc.dockerfile.
