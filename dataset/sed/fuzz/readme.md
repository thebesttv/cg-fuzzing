# sed Fuzzing Resources

This directory contains resources for fuzzing sed using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (based on sed command syntax)
- `in/` - Initial input corpus (sed script files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) is created based on sed command syntax and regular expressions.

The initial input corpus contains basic sed scripts created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f sed/fuzz.dockerfile -t sed-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm sed-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm sed-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: sed CLI binary
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: sed script files processed with -f flag
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses sed version 4.9, matching the bc.dockerfile.
