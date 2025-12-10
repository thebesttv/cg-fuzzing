# GDBM Fuzzing Resources

GDBM (GNU Database Manager) is a library for simple databases.

## Target Binary

- `gdbm_load` - Loads data from dump files into GDBM database

## External Resources

- dict: Created based on GDBM dump file format specification
- in/: Sample dump files created for fuzzing

## Usage

Build the fuzzing Docker image:
```bash
docker build -f gdbm/fuzz.dockerfile -t gdbm-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm gdbm-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm gdbm-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: gdbm_load CLI binary
- **Instrumentation**: afl-clang-lto (collision-free)
- **CMPLOG**: Enabled for better coverage
- **Input**: GDBM dump format files
- **Static linking**: For better performance

## Version

This fuzzing setup uses GDBM version 1.26, matching the bc.dockerfile.
