# optipng Fuzzing Resources

This directory contains resources for fuzzing optipng (PNG optimizer) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (PNG format tokens)
- `in/` - Initial input corpus (minimal PNG files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) is from:
- AFL++ png.dict: https://github.com/AFLplusplus/AFLplusplus/blob/stable/dictionaries/png.dict

The initial input corpus contains minimal PNG files created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f optipng/fuzz.dockerfile -t optipng-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm optipng-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm optipng-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: optipng CLI binary (PNG optimization tool)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: PNG image files
- **Options**: -simulate (don't write output, just test parsing)
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses optipng version 0.7.8, matching the bc.dockerfile.
