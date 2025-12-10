# YARA Fuzzing Resources

This directory contains resources for fuzzing YARA using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with YARA keywords
- `in/` - Initial input corpus (YARA rule files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on YARA language keywords and operators.

The initial input corpus contains basic YARA rule samples created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f yara/fuzz.dockerfile -t yara-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm yara-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm yara-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: yara CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: YARA rule files processed against /dev/null
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses YARA version 4.5.5, matching the bc.dockerfile.
