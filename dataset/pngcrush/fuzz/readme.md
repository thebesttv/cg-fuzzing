# pngcrush Fuzzing Resources

This directory contains resources for fuzzing pngcrush (PNG optimizer) using AFL++.

## Files

- `dict` - Dictionary file containing PNG chunk types and header
- `in/` - Initial input corpus with various PNG images
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) is from the AFL++ project:
- Source: https://github.com/AFLplusplus/AFLplusplus/blob/stable/dictionaries/png.dict

The initial input corpus contains small PNG files copied from the optipng project in this dataset.

## Usage

Build the fuzzing Docker image from the dataset directory:
```bash
cd dataset
docker build -f pngcrush/fuzz.dockerfile -t pngcrush-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm pngcrush-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm pngcrush-fuzz ./fuzz.sh -j 4
```

Monitor fuzzing progress (in another terminal):
```bash
docker exec -it <container_id> ./whatsup.sh
```

Or use watch mode:
```bash
docker exec -it <container_id> ./whatsup.sh -w
```

## Fuzzing Strategy

- **Target**: pngcrush CLI binary (PNG optimization tool)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of PNG chunk parsing
- **Input**: PNG image files
- **Static linking**: For better performance and reproducibility
- **Command**: `pngcrush <input> /tmp/out.png`

## Version

This fuzzing setup uses pngcrush version 1.8.13, matching the bc.dockerfile.
