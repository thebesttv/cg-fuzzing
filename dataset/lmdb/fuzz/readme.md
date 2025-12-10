# LMDB Fuzzing Resources

LMDB (Lightning Memory-Mapped Database) is a fast key-value store.

## Target Binary

- `mdb_load` - Loads data from dump files into LMDB database

## External Resources

- dict: Created based on LMDB dump file format specification
- in/: Sample dump files created for fuzzing

## Usage

Build the fuzzing Docker image:
```bash
docker build -f lmdb/fuzz.dockerfile -t lmdb-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm lmdb-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm lmdb-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: mdb_load CLI binary
- **Instrumentation**: afl-clang-lto (collision-free)
- **CMPLOG**: Enabled for better coverage
- **Input**: LMDB dump format files
- **Static linking**: For better performance

## Version

This fuzzing setup uses LMDB version 0.9.31, matching the bc.dockerfile.
