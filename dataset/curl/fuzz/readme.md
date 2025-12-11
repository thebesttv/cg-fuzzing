# curl Fuzzing Resources

This directory contains resources for fuzzing curl using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (URL schemes, HTTP tokens)
- `in/` - Initial input corpus (curl config files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on:
- curl manual page and documentation
- HTTP/URL specifications

The initial input corpus contains:
- curl config files with various URL schemes
- HTTP headers and options
- Edge cases (empty files)

## Usage

Build the fuzzing Docker image:
```bash
docker build -f curl/fuzz.dockerfile -t curl-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm curl-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm curl-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: curl CLI binary (config file parsing via `-K` option)
- **Note**: We fuzz config file parsing, not actual network operations
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: curl configuration files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses curl version 8.17.0, matching the bc.dockerfile.
