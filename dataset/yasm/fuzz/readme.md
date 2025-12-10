# yasm Fuzzing Resources

This directory contains resources for fuzzing yasm assembler using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with x86/x64 assembly keywords
- `in/` - Initial input corpus (assembly source files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

Dictionary keywords based on x86/x64 NASM-syntax assembly language.

The initial input corpus contains example assembly files created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f yasm/fuzz.dockerfile -t yasm-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm yasm-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm yasm-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: yasm CLI binary (assembler)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Assembly source files (.asm)
- **Output**: ELF object files (discarded to /dev/null)
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses yasm version 1.3.0, matching the bc.dockerfile.
