# libtasn1 Fuzzing Resources

This directory contains resources for fuzzing GNU libtasn1 asn1Parser using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (ASN.1 keywords)
- `in/` - Initial input corpus (ASN.1 definition files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created for this project based on ASN.1 syntax keywords.

The initial input corpus contains ASN.1 definition file samples, some from the libtasn1 test suite.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f libtasn1/fuzz.dockerfile -t libtasn1-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm libtasn1-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm libtasn1-fuzz ./fuzz.sh -j 4
```

Monitor fuzzing progress:
```bash
docker run -it --rm libtasn1-fuzz ./whatsup.sh
```

## Fuzzing Strategy

- **Target**: asn1Parser CLI binary with -c (check-only) option
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: ASN.1 definition files parsed for syntax checking
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses libtasn1 version 4.20.0, matching the bc.dockerfile.
