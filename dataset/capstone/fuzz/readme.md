# capstone Fuzzing Resources

This directory contains resources for fuzzing Capstone disassembly framework using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (architecture names, opcodes)
- `in/` - Initial input corpus (machine code samples for various architectures)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

- dict: Custom dictionary based on Capstone architecture identifiers and x86 opcodes
- in/: Machine code samples created for this project (x86-64, ARM)

## Usage

Build the fuzzing Docker image:
```bash
docker build -f capstone/fuzz.dockerfile -t capstone-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm capstone-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm capstone-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: cstool CLI binary (disassembles x64 machine code from file)
- **Instrumentation**: afl-clang-fast (AFL++ instrumentation)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Binary machine code files
- **Note**: Uses dynamic linking (common libraries only)

## Version

This fuzzing setup uses Capstone version 5.0.3, matching the bc.dockerfile.
