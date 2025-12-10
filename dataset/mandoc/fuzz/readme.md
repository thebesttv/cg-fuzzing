# mandoc Fuzzing Resources

This directory contains resources for fuzzing mandoc (man page formatter) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (mdoc/man macros)
- `in/` - Initial input corpus (man page files in various formats)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created for this project based on mdoc and man macro commands.

The initial input corpus contains:
- `simple.1` - Simple mdoc format man page
- `man.1` - Traditional man format man page
- `func.3` - Library function documentation (section 3)
- `list.1` - Man page with lists
- `table.7` - Man page with table

## Usage

Build the fuzzing Docker image:
```bash
docker build -f mandoc/fuzz.dockerfile -t mandoc-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm mandoc-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm mandoc-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: mandoc binary (man page formatter)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Man page files in mdoc or traditional man format
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses mandoc version 1.14.6, matching the bc.dockerfile.
