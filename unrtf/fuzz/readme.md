# unrtf Fuzzing Resources

This directory contains resources for fuzzing unrtf (RTF to HTML/text converter) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (RTF control words)
- `in/` - Initial input corpus (minimal RTF files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) is based on:
- AFL++ rtf.dict: https://github.com/AFLplusplus/AFLplusplus/blob/stable/dictionaries/rtf.dict
- Extended with additional RTF control words

The initial input corpus contains minimal RTF files created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f unrtf/fuzz.dockerfile -t unrtf-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm unrtf-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm unrtf-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: unrtf CLI binary (converts RTF to HTML/text)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: RTF document files
- **Options**: --nopict (skip picture processing for speed)
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses unrtf version 0.21.10, matching the bc.dockerfile.
