# picohttpparser Fuzzing Resources

This directory contains resources for fuzzing picohttpparser (fast HTTP request/response parser) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (HTTP methods, headers, status codes, etc.)
- `in/` - Initial input corpus (HTTP requests and responses)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file contains common HTTP methods, headers, status codes, and tokens relevant for HTTP parsing.

The initial input corpus contains sample HTTP requests and responses covering:
- Simple GET requests
- POST requests with body
- HTTP responses
- Chunked transfer encoding
- Requests with multiple headers

## Usage

Build the fuzzing Docker image:
```bash
docker build -f picohttpparser/fuzz.dockerfile -t picohttpparser-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm picohttpparser-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm picohttpparser-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: picohttpparser_fuzz binary (exercises HTTP request, response, headers, and chunked decoding)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: HTTP request/response data
- **Static linking**: For better performance and reproducibility

## Functions Tested

The fuzzing harness exercises all main picohttpparser functions:
- `phr_parse_request()` - Parse HTTP requests
- `phr_parse_response()` - Parse HTTP responses
- `phr_parse_headers()` - Parse HTTP headers
- `phr_decode_chunked()` - Decode chunked transfer encoding

## Version

This fuzzing setup uses picohttpparser from the master branch (latest commit), matching the bc.dockerfile.
