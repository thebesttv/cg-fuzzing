# snappy Fuzzing Resources

## Project Information
- **Project**: Snappy (Compression Library by Google)
- **Version**: 1.2.1
- **Source**: https://github.com/google/snappy

## External Resources

- dict: Custom dictionary for compression fuzzing (common patterns, edge cases)
- in/: Text and binary seed inputs for compression testing

## Fuzzing Target

The fuzzing target exercises the Snappy compression/decompression API:
- Tests `snappy_compress()` with various input data
- Tests `snappy_uncompress()` for decompression
- Uses AFL persistent mode for performance

## Usage

```bash
cd dataset
docker build -f snappy/fuzz.dockerfile -t snappy-fuzz .
docker run -it --rm snappy-fuzz
```

In the container, use:
- `/work/bin-fuzz` - AFL++ fuzzing binary
- `/work/bin-cmplog` - AFL++ CMPLOG binary
- `/work/bin-cov` - LLVM coverage binary
- `/work/bin-uftrace` - uftrace profiling binary
- `/work/fuzz.sh` - Start fuzzing
- `/work/whatsup.sh` - Monitor fuzzing progress

## Example Commands

```bash
# Start fuzzing with 1 core (interactive)
./fuzz.sh

# Start fuzzing with 4 cores (background)
./fuzz.sh -j 4

# Monitor progress
./whatsup.sh

# Watch progress (auto-refresh)
./whatsup.sh -w
```
