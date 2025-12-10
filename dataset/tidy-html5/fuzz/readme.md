# tidy-html5 Fuzzing Resources

This directory contains resources for fuzzing tidy-html5 using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (HTML tags and tokens)
- `in/` - Initial input corpus (HTML files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) contains common HTML tags, attributes, and entities.

The initial input corpus contains sample HTML files with various structures.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f tidy-html5/fuzz.dockerfile -t tidy-html5-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm tidy-html5-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm tidy-html5-fuzz ./fuzz.sh -j 4
```

Monitor progress:
```bash
docker run -it --rm tidy-html5-fuzz ./whatsup.sh
```

## Fuzzing Strategy

- **Target**: tidy CLI binary with `-q` (quiet mode) for faster fuzzing
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: HTML files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses tidy-html5 version 5.8.0, matching the bc.dockerfile.
