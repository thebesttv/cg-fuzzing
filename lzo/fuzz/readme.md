# lzo Fuzzing Resources

This directory contains resources for fuzzing lzo using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing containing LZO-related tokens
- `in/` - Initial input corpus (various data samples)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created for this project, containing:
- LZO file signatures
- Common byte patterns in compressed data
- Header magic bytes

The initial input corpus contains basic data samples:
- Text files
- Binary data
- Empty and edge case files

## Usage

Build the fuzzing Docker image:
```bash
docker build -f lzo/fuzz.dockerfile -t lzo-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm lzo-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm lzo-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: lzopack CLI tool (compresses files using LZO algorithm)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Files to be compressed by lzopack
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses lzo version 2.10, matching the bc.dockerfile.
