# tinycbor Fuzzing Resources

This directory contains resources for fuzzing tinycbor using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with CBOR-specific tokens
- `in/` - Initial input corpus (CBOR binary files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on RFC 7049 (CBOR) encoding specification.

The initial input corpus contains basic CBOR samples created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f tinycbor/fuzz.dockerfile -t tinycbor-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm tinycbor-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm tinycbor-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: cbordump CLI binary (parses CBOR files and outputs to stdout)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Binary CBOR data files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses tinycbor version 0.6.1, matching the bc.dockerfile.
