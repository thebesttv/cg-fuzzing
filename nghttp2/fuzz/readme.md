# nghttp2 Fuzzing Resources

This directory contains resources for fuzzing nghttp2's HPACK decoder using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (HPACK patterns)
- `in/` - Initial input corpus (HPACK encoded data)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) is created based on HTTP/2 HPACK encoding specification.

The initial input corpus contains minimal HPACK encoded binary sequences.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f nghttp2/fuzz.dockerfile -t nghttp2-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm nghttp2-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm nghttp2-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: hd_decode binary (custom HPACK decoder test program using libnghttp2)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Binary files containing HPACK encoded headers
- **Static linking**: For better performance and reproducibility

## About nghttp2

nghttp2 is an implementation of the HTTP/2 protocol in C. HPACK is the header 
compression algorithm used in HTTP/2 (RFC 7541).

## Version

This fuzzing setup uses nghttp2 version 1.68.0, matching the bc.dockerfile.
