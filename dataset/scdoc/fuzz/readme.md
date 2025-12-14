# scdoc Fuzzing Resources

This directory contains resources for fuzzing scdoc using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (scdoc man page format tokens)
- `in/` - Initial input corpus (sample .scd files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

- Dictionary file created specifically for scdoc man page format
- Input corpus contains hand-crafted .scd examples

## Usage

Build the fuzzing Docker image:
```bash
cd dataset
docker build -f scdoc/fuzz.dockerfile -t scdoc-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm scdoc-fuzz
./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm scdoc-fuzz
./fuzz.sh -j 4
```

Monitor fuzzing progress:
```bash
./whatsup.sh
```

## Fuzzing Strategy

- **Target**: scdoc CLI binary (man page generator from markdown)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: .scd files (scdoc man page format) read from stdin
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses scdoc version 1.11.3, matching the bc.dockerfile.
