# readstat Fuzzing Resources

This directory contains resources for fuzzing readstat using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (SAS, SPSS, Stata keywords and magic numbers)
- `in/` - Initial input corpus (minimal SAS, SPSS, Stata files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary and input samples were created based on:
- ReadStat documentation: https://github.com/WizardMac/ReadStat
- SAS, SPSS, and Stata file format specifications

## Usage

Build the fuzzing Docker image (from dataset directory):
```bash
cd dataset
docker build -f readstat/fuzz.dockerfile -t readstat-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm readstat-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm readstat-fuzz ./fuzz.sh -j 4
```

Monitor fuzzing progress:
```bash
docker exec <container_id> ./whatsup.sh
```

## Fuzzing Strategy

- **Target**: readstat CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Statistical data files (SAS, SPSS, Stata formats)
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses readstat version 1.1.9, matching the bc.dockerfile.
