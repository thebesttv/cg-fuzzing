# ncompress Fuzzing Resources

This directory contains resources for fuzzing ncompress (classic Unix compress utility) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (LZW/compress format tokens)
- `in/` - Initial input corpus (.Z compressed files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on:
- Unix compress (.Z) file format specification
- LZW compression header patterns

The initial input corpus contains minimal .Z format samples created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f ncompress/fuzz.dockerfile -t ncompress-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm ncompress-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm ncompress-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: compress CLI binary (decompression mode via -d)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: .Z compressed files (decompress mode)
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses ncompress version 5.0, matching the bc.dockerfile.
