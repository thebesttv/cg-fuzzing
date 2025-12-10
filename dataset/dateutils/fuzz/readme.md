# dateutils Fuzzing Resources

This directory contains resources for fuzzing dateutils using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (date formats and tokens)
- `in/` - Initial input corpus (date string files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) contains common date format strings, month/day names, and format specifiers.

The initial input corpus contains sample date strings in various formats.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f dateutils/fuzz.dockerfile -t dateutils-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm dateutils-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm dateutils-fuzz ./fuzz.sh -j 4
```

Monitor progress:
```bash
docker run -it --rm dateutils-fuzz ./whatsup.sh
```

## Fuzzing Strategy

- **Target**: dconv (date converter) CLI binary with `-f` (read from file)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Date strings in various formats
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses dateutils version 0.4.11, matching the bc.dockerfile.
