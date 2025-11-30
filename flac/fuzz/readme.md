# flac Fuzzing Resources

This directory contains resources for fuzzing FLAC using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (FLAC format tokens)
- `in/` - Initial input corpus (minimal FLAC, WAV, AIFF, and raw audio files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

- dict: Custom dictionary based on FLAC specification and command-line options
- in/: Minimal audio files created for this project

## Usage

Build the fuzzing Docker image:
```bash
docker build -f flac/fuzz.dockerfile -t flac-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm flac-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm flac-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: flac CLI binary (decode mode with `-d -c -f` options)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: FLAC, WAV, AIFF, and raw audio files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses FLAC version 1.5.0, matching the bc.dockerfile.
