# giflib Fuzzing Resources

This directory contains resources for fuzzing giflib (GIF library) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (GIF format tokens)
- `in/` - Initial input corpus (minimal GIF files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on the GIF89a specification.

The initial input corpus contains minimal GIF files created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f giflib/fuzz.dockerfile -t giflib-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm giflib-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm giflib-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: giftext CLI binary (reads GIF metadata)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: GIF image files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses giflib version 5.2.2, matching the bc.dockerfile.
