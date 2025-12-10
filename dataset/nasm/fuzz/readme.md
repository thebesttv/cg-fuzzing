# nasm Fuzzing Resources

This directory contains resources for fuzzing nasm using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (x86/x64 assembly tokens)
- `in/` - Initial input corpus (assembly source files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on:
- NASM documentation and instruction reference
- x86/x64 assembly syntax

The initial input corpus contains:
- Simple assembly programs (32-bit and 64-bit)
- Macro examples
- Edge cases (empty files, invalid syntax)

## Usage

Build the fuzzing Docker image:
```bash
docker build -f nasm/fuzz.dockerfile -t nasm-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm nasm-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm nasm-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: nasm CLI binary (assembler)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Assembly source files (.asm)
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses nasm version 2.16.03, matching the bc.dockerfile.
