# lzop Fuzzing Resources

This directory contains resources for fuzzing lzop using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (lzo magic bytes and options)
- `in/` - Initial input corpus (compressed lzo files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

- dict: Custom dictionary based on lzop file format and command options
- in/: Sample lzo compressed files for initial corpus

## Usage

Build the fuzzing Docker image:
```bash
docker build -f lzop/fuzz.dockerfile -t lzop-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm lzop-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm lzop-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: lzop CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Compressed .lzo files processed with -d (decompress) -c (stdout)
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses lzop version 1.04, matching the bc.dockerfile.
