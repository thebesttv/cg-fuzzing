# ctags Fuzzing Resources

This directory contains resources for fuzzing Universal Ctags using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (programming language keywords)
- `in/` - Initial input corpus (sample source code files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) is created based on common programming language keywords.

The initial input corpus contains basic source code samples in C, Python, JavaScript, etc.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f ctags/fuzz.dockerfile -t ctags-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm ctags-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm ctags-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: ctags CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Source code files that ctags parses to extract tags
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses Universal Ctags version 6.2.1, matching the bc.dockerfile.
