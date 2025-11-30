# nettle Fuzzing Resources

This directory contains resources for fuzzing GNU nettle sexp-conv using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (S-expression syntax)
- `in/` - Initial input corpus (S-expression files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created for this project based on S-expression syntax.

The initial input corpus contains S-expression samples created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f nettle/fuzz.dockerfile -t nettle-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm nettle-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm nettle-fuzz ./fuzz.sh -j 4
```

Monitor fuzzing progress:
```bash
docker run -it --rm nettle-fuzz ./whatsup.sh
```

## Fuzzing Strategy

- **Target**: sexp-conv CLI binary (S-expression converter, reads from stdin)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: S-expression data processed by sexp-conv
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses nettle version 3.10.2, matching the bc.dockerfile.
