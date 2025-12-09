# libvpx Fuzzing Resources

This directory contains resources for fuzzing libvpx (VP8/VP9 video codec) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with VP8/VP9 format tokens
- `in/` - Initial input corpus (IVF video files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

- Dictionary: Created based on VP8/VP9 and IVF format specifications
- Input corpus: Minimal IVF files created for this project

## Usage

Build the fuzzing Docker image:
```bash
docker build -f libvpx/fuzz.dockerfile -t libvpx-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm libvpx-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm libvpx-fuzz ./fuzz.sh -j 4
```

Monitor fuzzing progress:
```bash
docker run -it --rm libvpx-fuzz ./whatsup.sh
```

## Fuzzing Strategy

- **Target**: vpxdec (simple_decoder) binary that decodes VP8/VP9 video files
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: IVF format video files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses libvpx version 1.14.1, matching the bc.dockerfile.
