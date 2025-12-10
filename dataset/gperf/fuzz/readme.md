# gperf Fuzzing Resources

This directory contains resources for fuzzing gperf (GNU perfect hash function generator) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with gperf keywords
- `in/` - Initial input corpus (gperf input files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created specifically for this project based on gperf input file syntax.

The initial input corpus contains basic gperf input samples created for this project:
- `simple.gperf` - Minimal gperf input with basic keywords
- `struct.gperf` - Input with struct definition and options
- `keywords.gperf` - C language keywords
- `days.gperf` - Days of the week with case-insensitivity
- `http.gperf` - HTTP methods with various options

## Usage

Build the fuzzing Docker image:
```bash
docker build -f gperf/fuzz.dockerfile -t gperf-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm gperf-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm gperf-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: gperf CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: gperf input files (keyword lists with optional options)
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses gperf version 3.1, matching the bc.dockerfile.
