# sqlite-harness Fuzzing Resources

This directory contains resources for fuzzing SQLite using the `sqlite_ossfuzz` harness with AFL++.

## Harness

Unlike the `sqlite` project which fuzzes the sqlite3 CLI binary, this project uses the `ossfuzz.c` harness from the SQLite source tree. This harness is designed for OSS-Fuzz and provides:

1. In-memory database fuzzing (no file I/O)
2. Progress callbacks to prevent infinite loops
3. Memory and resource limits
4. Selector byte for configuration (foreign keys, output limits)
5. Time-based cutoff to prevent hangs

The harness takes raw SQL input and executes it against an in-memory SQLite database.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (same as sqlite project)
- `in/` - Initial input corpus (SQL files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) is based on SQLite's SQL syntax documentation:
- Reference: https://www.sqlite.org/lang.html

The harness `ossfuzz.c` is from the SQLite source tree:
- Source: https://github.com/sqlite/sqlite/blob/master/test/ossfuzz.c

## Usage

Build the fuzzing Docker image:
```bash
docker build -f sqlite-harness/fuzz.dockerfile -t sqlite-harness-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm sqlite-harness-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm sqlite-harness-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: sqlite_ossfuzz harness (library-level fuzzing)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Raw SQL statements
- **Static linking**: For better performance and reproducibility

## Bitcode Extraction

Build the bitcode Docker image:
```bash
docker build -f sqlite-harness/bc.dockerfile -t sqlite-harness-bc .
```

Copy bitcode files:
```bash
container_id=$(docker create sqlite-harness-bc)
docker cp "$container_id:/home/SVF-tools/bc/." sqlite-harness/bc/
docker rm "$container_id"
```

## Version

This fuzzing setup uses SQLite version 3.51.0, matching the sqlite project.
