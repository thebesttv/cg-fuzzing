# bsdiff/bspatch Fuzzing Resources

## Project Info
- **Project**: bsdiff/bspatch - Binary diff and patch utilities
- **Source**: https://github.com/mendsley/bsdiff
- **Version**: master branch

## Fuzzing Resources

### Dictionary
- `dict`: Custom dictionary with binary file format magic numbers and patterns
- Includes bsdiff patch headers, common binary formats (ELF, PNG, etc.), and BZ2 compression markers

### Input Corpus
- `in/`: Sample binary files of various types
  - ELF header
  - Zero-filled blocks
  - Random data
  - Text files

### Scripts
- `fuzz.sh`: Start AFL++ fuzzing with parallel support
- `whatsup.sh`: Monitor fuzzing progress

## Target Binary
We fuzz **bspatch** as it processes patch files, which is a more interesting attack surface than bsdiff itself.

## Usage

```bash
docker build -f bsdiff/fuzz.dockerfile -t bsdiff-fuzz .
docker run -it --rm bsdiff-fuzz ./fuzz.sh
```

For parallel fuzzing:
```bash
docker run -it --rm bsdiff-fuzz ./fuzz.sh -j 4
```
