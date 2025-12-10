# libucl Fuzzing Resources

This directory contains resources for fuzzing libucl (Universal Config Library) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (UCL syntax)
- `in/` - Initial input corpus (UCL config files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) is created based on UCL syntax documentation.

The initial input corpus contains basic UCL config samples created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f libucl/fuzz.dockerfile -t libucl-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm libucl-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm libucl-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: ucl_tool CLI binary (UCL config parser/validator)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: UCL config files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses libucl version 0.9.2, matching the bc.dockerfile.
