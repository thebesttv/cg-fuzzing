# GNU indent Fuzzing Resources

This directory contains resources for fuzzing GNU indent using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with C language keywords
- `in/` - Initial input corpus (C source files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) contains C language keywords created for this project.

The initial input corpus contains basic C code samples created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f indent/fuzz.dockerfile -t indent-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm indent-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm indent-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: indent CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: C source files to format
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses GNU indent version 2.2.13, matching the bc.dockerfile.
