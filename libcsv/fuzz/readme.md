# libcsv Fuzzing Resources

This directory contains resources for fuzzing libcsv using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing containing CSV-related tokens
- `in/` - Initial input corpus (CSV samples)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created for this project, containing common CSV elements:
- Delimiters (comma, semicolon, tab)
- Quote characters
- Escape sequences
- Common field values

The initial input corpus contains basic CSV samples created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f libcsv/fuzz.dockerfile -t libcsv-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm libcsv-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm libcsv-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: csvinfo CLI tool (parses and analyzes CSV files)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: CSV files processed by csvinfo
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses libcsv version 3.0.3, matching the bc.dockerfile.
