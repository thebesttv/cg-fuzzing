# libjpeg-turbo Fuzzing Resources

This directory contains resources for fuzzing libjpeg-turbo using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (JPEG markers and syntax)
- `in/` - Initial input corpus (JPEG files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) is from AFL++ dictionaries:
- Source: https://github.com/AFLplusplus/AFLplusplus/blob/stable/dictionaries/jpeg.dict

The initial input corpus contains minimal JPEG samples created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f libjpeg-turbo/fuzz.dockerfile -t libjpeg-turbo-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm libjpeg-turbo-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm libjpeg-turbo-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: djpeg CLI binary (JPEG decoder, same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: JPEG image files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses libjpeg-turbo version 3.1.2, matching the bc.dockerfile.
