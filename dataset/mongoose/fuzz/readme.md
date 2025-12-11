# mongoose Fuzzing Resources

This directory contains resources for fuzzing mongoose (Embedded Web Server Library) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with HTTP/web server tokens
- `in/` - Initial input corpus (HTTP request/response files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) contains HTTP protocol tokens and common web server strings, 
based on standard HTTP specifications and common fuzzing dictionaries.

The initial input corpus contains basic HTTP requests and responses created for this project:
- GET requests (simple, with headers, with query strings)
- POST requests (JSON body, form-urlencoded body)
- PUT requests
- Chunked transfer encoding
- HTTP responses

## Usage

Build the fuzzing Docker image:
```bash
docker build -f mongoose/fuzz.dockerfile -t mongoose-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm mongoose-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm mongoose-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: mongoose_fuzz harness binary that exercises HTTP parsing functionality
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: HTTP request/response data files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses mongoose version 7.20, matching the bc.dockerfile.
