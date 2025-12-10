# grep Fuzzing Resources

This directory contains resources for fuzzing grep using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (based on regular expression syntax)
- `in/` - Initial input corpus (regex pattern files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) is created based on POSIX and extended regular expression syntax.

The initial input corpus contains basic regex patterns created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f grep/fuzz.dockerfile -t grep-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm grep-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm grep-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: grep CLI binary
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Pattern files read with -f flag, matched against /dev/null
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses grep version 3.12, matching the bc.dockerfile.
