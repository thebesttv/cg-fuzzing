# samurai Fuzzing Resources

This directory contains resources for fuzzing samurai using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (Ninja build file keywords)
- `in/` - Initial input corpus (sample .ninja build files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

- Dictionary: Created based on Ninja build language keywords
- Input corpus: Sample .ninja build files created for this project

## Usage

Build the fuzzing Docker image:
```bash
cd dataset
docker build -f samurai/fuzz.dockerfile -t samurai-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm samurai-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm samurai-fuzz ./fuzz.sh -j 4
```

Monitor fuzzing progress:
```bash
docker run -it --rm samurai-fuzz ./whatsup.sh
```

## Fuzzing Strategy

- **Target**: samu (samurai binary, ninja-compatible build tool - same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Ninja build files (.ninja)
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses samurai version 1.2, matching the bc.dockerfile.
