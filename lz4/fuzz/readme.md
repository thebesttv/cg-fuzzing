# lz4 Fuzzing Resources

This directory contains resources for fuzzing lz4 using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (lz4 format tokens)
- `in/` - Initial input corpus (lz4 compressed files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) is based on the lz4 frame format specification.
Reference: https://github.com/lz4/lz4/blob/dev/doc/lz4_Frame_format.md

The initial input corpus contains basic lz4 compressed samples.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f lz4/fuzz.dockerfile -t lz4-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm lz4-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm lz4-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: lz4 CLI binary (decompression mode)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: lz4 compressed files decompressed with `-d -f -c` flags
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses lz4 version 1.10.0, matching the bc.dockerfile.

## About lz4

LZ4 is a lossless data compression algorithm that is focused on
compression and decompression speed. It belongs to the LZ77 family
of byte-oriented compression schemes.

The decompression path is particularly interesting for fuzzing as it needs to:
- Parse and validate lz4 frame headers
- Handle block decompression
- Process literal and match tokens
- Verify checksums (optional)

LZ4 uses simple memory allocation callbacks which makes it a good
target for studying function pointer behavior.
