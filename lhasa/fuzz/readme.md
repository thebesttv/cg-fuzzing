# lhasa (lha) Fuzzing Resources

This directory contains resources for fuzzing lha using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (LHA/LZH format tokens)
- `in/` - Initial input corpus (LZH archive files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on:
- LHA/LZH file format specification
- Common LHA method identifiers (-lh0-, -lh5-, etc.)
- Header structure markers

The initial input corpus contains:
- `minimal.lzh` - Minimal LZH archive with -lh0- method
- `lh5.lzh` - LZH archive with -lh5- compression method
- `empty.lzh` - LZH with empty file
- `bad_method.lzh` - Invalid method ID for edge case testing
- `header_only.lzh` - Header without complete data

## Usage

Build the fuzzing Docker image:
```bash
docker build -f lhasa/fuzz.dockerfile -t lhasa-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm lhasa-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm lhasa-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: lha CLI binary with `t` command (test/list mode)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: LZH/LHA archive files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses lhasa version 0.4.0, matching the bc.dockerfile.
