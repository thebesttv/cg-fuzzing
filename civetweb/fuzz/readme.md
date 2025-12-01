# civetweb Fuzzing Resources

This directory contains resources for fuzzing civetweb HTTP server library using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (HTTP/1.1 keywords from civetweb project)
- `in/` - Initial input corpus (URL encoded strings, cookies, HTTP headers)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress
- `harness/` - AFL++ harness source code

## External Resources

The dictionary file (`dict`) is from the civetweb project:
- Source: https://github.com/civetweb/civetweb/blob/master/fuzztest/http1.dict

## Usage

Build the fuzzing Docker image:
```bash
docker build -f civetweb/fuzz.dockerfile -t civetweb-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm civetweb-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm civetweb-fuzz ./fuzz.sh -j 4
```

Monitor fuzzing progress:
```bash
docker run -it --rm civetweb-fuzz ./whatsup.sh
```

## Fuzzing Strategy

- **Target**: civetweb_url_fuzz binary (URL/cookie parsing fuzzer)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: URL-encoded strings, cookies, HTTP headers
- **Focus**: Tests mg_url_decode, mg_get_var, and mg_get_cookie functions

## Version

This fuzzing setup uses civetweb version 1.16, matching the bc.dockerfile.
