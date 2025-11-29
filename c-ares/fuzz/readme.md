# c-ares Fuzzing Resources

This directory contains resources for fuzzing c-ares's adig tool using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (DNS patterns)
- `in/` - Initial input corpus (hostnames to query)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) is created based on DNS hostname patterns and record types.

The initial input corpus contains basic hostname samples for adig to parse.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f c-ares/fuzz.dockerfile -t c-ares-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm c-ares-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm c-ares-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: adig CLI binary (DNS lookup tool from c-ares)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Files containing hostnames passed via `-f` option
- **Static linking**: For better performance and reproducibility

## About c-ares

c-ares is a C library for asynchronous DNS requests (including name resolves).
The adig tool is a command-line DNS lookup utility built with c-ares.

## Version

This fuzzing setup uses c-ares version 1.34.5, matching the bc.dockerfile.
