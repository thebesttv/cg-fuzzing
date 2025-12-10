# gifsicle Fuzzing Resources

This directory contains resources for fuzzing gifsicle using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (GIF format tokens)
- `in/` - Initial input corpus (small GIF files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on:
- GIF89a specification
- gifsicle command-line options

The initial input corpus contains minimal GIF samples created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f gifsicle/fuzz.dockerfile -t gifsicle-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm gifsicle-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm gifsicle-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: gifsicle CLI binary (GIF manipulation tool)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: GIF image files processed with `--info` option
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses gifsicle version 1.96, matching the bc.dockerfile.
