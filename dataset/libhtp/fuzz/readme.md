# libhtp Fuzzing Resources

This directory contains resources for fuzzing libhtp using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with HTTP keywords
- `in/` - Initial input corpus (HTTP request samples)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) contains HTTP/1.1 protocol keywords created for this project.
The initial input corpus contains basic HTTP request samples.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f libhtp/fuzz.dockerfile -t libhtp-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm libhtp-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm libhtp-fuzz ./fuzz.sh -j 4
```

Monitor fuzzing progress:
```bash
docker run -it --rm libhtp-fuzz ./whatsup.sh
```

## Fuzzing Strategy

- **Target**: test_fuzz binary (HTTP parser fuzzer from libhtp)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: HTTP request data files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses libhtp version 0.5.52, matching the bc.dockerfile.
