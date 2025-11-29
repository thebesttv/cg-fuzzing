# jo Fuzzing Resources

This directory contains resources for fuzzing jo using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing
- `in/` - Initial input corpus
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created specifically for jo, containing:
- JSON tokens
- jo-specific syntax (arrays, objects, options)
- Special characters and escape sequences

The initial input corpus contains basic jo argument patterns.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f jo/fuzz.dockerfile -t jo-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm jo-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm jo-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: jo CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Command line arguments passed via xargs
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses jo version 1.9, matching the bc.dockerfile.
