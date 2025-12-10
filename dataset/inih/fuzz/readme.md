# inih Fuzzing Resources

This directory contains resources for fuzzing inih INI parser using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (INI syntax tokens)
- `in/` - Initial input corpus (INI files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on INI file format specification.

The initial input corpus contains sample INI files covering various INI features.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f inih/fuzz.dockerfile -t inih-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm inih-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm inih-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: ini_fuzz binary (harness that parses INI files)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: INI configuration files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses inih version r62.
