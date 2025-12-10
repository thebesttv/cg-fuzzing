# ssdeep Fuzzing Resources

This directory contains resources for fuzzing ssdeep (fuzzy hashing) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with ssdeep patterns
- `in/` - Initial input corpus (various file types for hashing)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created specifically for this project based on ssdeep hash format.

The initial input corpus contains:
- `text.txt` - Simple text file
- `random.bin` - Random binary data
- `empty.txt` - Empty file
- `repeated.txt` - File with repeated characters

## Usage

Build the fuzzing Docker image:
```bash
docker build -f ssdeep/fuzz.dockerfile -t ssdeep-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm ssdeep-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm ssdeep-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: ssdeep CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Files of various types for fuzzy hashing
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses ssdeep version 2.14.1, matching the bc.dockerfile.
