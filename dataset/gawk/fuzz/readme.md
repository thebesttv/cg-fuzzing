# gawk Fuzzing Resources

This directory contains resources for fuzzing gawk using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (based on AWK language syntax)
- `in/` - Initial input corpus (AWK script files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) is created based on AWK/GAWK language syntax, including built-in functions, special variables, and operators.

The initial input corpus contains basic AWK scripts created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f gawk/fuzz.dockerfile -t gawk-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm gawk-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm gawk-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: gawk CLI binary
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: AWK script files read with -f flag, processing /dev/null
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses gawk version 5.3.2, matching the bc.dockerfile.
