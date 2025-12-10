# jbig2dec Fuzzing Resources

This directory contains resources for fuzzing jbig2dec using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (JBIG2 format tokens)
- `in/` - Initial input corpus (minimal JBIG2 files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on:
- ISO/IEC 14492 JBIG2 specification
- JBIG2 segment types and format structures

The initial input corpus contains minimal JBIG2 samples created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f jbig2dec/fuzz.dockerfile -t jbig2dec-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm jbig2dec-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm jbig2dec-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: jbig2dec CLI binary (JBIG2 image decoder)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: JBIG2 compressed image files
- **Static linking**: For better performance and reproducibility

## Note

JBIG2 is a bi-level image compression standard, commonly used in PDF documents.
This tool decodes JBIG2 streams to PBM or PNG format.

## Version

This fuzzing setup uses jbig2dec version 0.20, matching the bc.dockerfile.
