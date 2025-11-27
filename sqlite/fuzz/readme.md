# SQLite Fuzzing Resources

This directory contains resources for fuzzing SQLite using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with SQL keywords
- `in/` - Initial input corpus (SQL files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) contains SQLite SQL keywords and operators based on SQLite's SQL syntax documentation:
- Reference: https://www.sqlite.org/lang.html

The initial input corpus contains basic SQL samples created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f sqlite/fuzz.dockerfile -t sqlite-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm sqlite-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm sqlite-fuzz ./fuzz.sh -j 4
```

Monitor fuzzing progress:
```bash
docker run -it --rm sqlite-fuzz ./whatsup.sh
```

## Fuzzing Strategy

- **Target**: sqlite3 CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: SQL files read from stdin
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses SQLite version 3.51.0, matching the bc.dockerfile.
