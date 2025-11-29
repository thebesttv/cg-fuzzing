# gettext Fuzzing Resources

This directory contains resources for fuzzing gettext msgfmt using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with PO file keywords
- `in/` - Initial input corpus (PO files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

- dict: Created based on GNU gettext PO file format specification
- in/: Sample PO files created for this project

## Usage

Build the fuzzing Docker image:
```bash
docker build -f gettext/fuzz.dockerfile -t gettext-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm gettext-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm gettext-fuzz ./fuzz.sh -j 4
```

Monitor fuzzing progress:
```bash
docker run -it --rm gettext-fuzz ./whatsup.sh
```

## Fuzzing Strategy

- **Target**: msgfmt CLI binary (PO to MO file compiler)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: PO (Portable Object) files for translation
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses gettext version 0.23.1, matching the bc.dockerfile.
