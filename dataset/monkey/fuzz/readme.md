# monkey Fuzzing Resources

This directory contains resources for fuzzing monkey web server using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (monkey configuration keywords)
- `in/` - Initial input corpus (monkey configuration files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary and input corpus were created specifically for this project based on monkey configuration syntax.

## Usage

Build the fuzzing Docker image:
```bash
cd dataset
docker build -f monkey/fuzz.dockerfile -t monkey-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm monkey-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm monkey-fuzz ./fuzz.sh -j 4
```

Monitor fuzzing progress:
```bash
docker run -it --rm monkey-fuzz ./whatsup.sh -w
```

## Fuzzing Strategy

- **Target**: monkey binary with configuration file input
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: monkey configuration files (`.conf`)
- **Static linking**: For better performance and reproducibility
- **Command**: `monkey -s <config_file>` loads configuration and validates it

## Version

This fuzzing setup uses monkey version 1.5.5, matching the bc.dockerfile.

## Note about Bitcode

The bc.dockerfile generates individual bitcode files for each object file rather than a single linked bitcode file. This is due to monkey's use of thread-local storage (TLS) which causes "symbol multiply defined" errors during LLVM bitcode linking. The individual .o.bc files can still be used for static analysis on a per-module basis.
