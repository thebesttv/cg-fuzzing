# datamash Fuzzing Resources

This directory contains resources for fuzzing GNU datamash using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing
- `in/` - Initial input corpus (tabular data files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created for this project based on datamash operations and options.

The initial input corpus contains basic tabular data samples created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f datamash/fuzz.dockerfile -t datamash-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm datamash-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm datamash-fuzz ./fuzz.sh -j 4
```

Monitor fuzzing progress:
```bash
docker run -it --rm datamash-fuzz ./whatsup.sh
```

## Fuzzing Strategy

- **Target**: datamash CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Tabular data processed with 'sum 1' operation (reads from stdin)
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses datamash version 1.9, matching the bc.dockerfile.
