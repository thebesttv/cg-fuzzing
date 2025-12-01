# pv (Pipe Viewer) Fuzzing Resources

This directory contains resources for fuzzing pv (Pipe Viewer) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (pv command line options)
- `in/` - Initial input corpus (command line argument combinations)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created for this project based on:
- Common byte patterns (null bytes, newlines, etc.)
- Text patterns
- Special characters

The initial input corpus contains:
- `simple.bin` - Simple text data
- `binary.bin` - Binary data with various byte values
- `lines.txt` - Multi-line text
- `zeros.bin` - Null byte data

## Usage

Build the fuzzing Docker image:
```bash
docker build -f pv/fuzz.dockerfile -t pv-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm pv-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm pv-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: pv binary (Pipe Viewer)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Binary/text data files passed as file argument with -q flag
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses pv version 1.9.7, matching the bc.dockerfile.
