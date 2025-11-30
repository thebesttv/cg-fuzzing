# diction Fuzzing Resources

This directory contains resources for fuzzing GNU diction using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing
- `in/` - Initial input corpus (text files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created for this project based on common English words and phrases that diction checks for.

The initial input corpus contains basic text samples with common diction issues.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f diction/fuzz.dockerfile -t diction-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm diction-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm diction-fuzz ./fuzz.sh -j 4
```

Monitor fuzzing progress:
```bash
docker run -it --rm diction-fuzz ./whatsup.sh
```

## Fuzzing Strategy

- **Target**: diction CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Text files analyzed for writing style issues
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses diction version 1.11, matching the bc.dockerfile.
