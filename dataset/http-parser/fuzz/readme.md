# http-parser Fuzzing Resources

This directory contains resources for fuzzing http-parser (HTTP request/response parser) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (HTTP methods, headers, etc.)
- `in/` - Initial input corpus (HTTP requests and responses)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file contains common HTTP methods, headers, and tokens.

The initial input corpus contains sample HTTP requests and responses.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f http-parser/fuzz.dockerfile -t http-parser-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm http-parser-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm http-parser-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: http_parser_fuzz binary (exercises HTTP request, response, and both parsing modes)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: HTTP request/response data
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses http-parser version 2.9.4, matching the bc.dockerfile.
