# iniparser Fuzzing Resources

This directory contains resources for fuzzing iniparser using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with INI-specific tokens
- `in/` - Initial input corpus (INI configuration files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on INI file syntax conventions.

The initial input corpus contains basic INI samples created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f iniparser/fuzz.dockerfile -t iniparser-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm iniparser-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm iniparser-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: parse example binary (parses INI files and dumps content)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: INI configuration files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses iniparser version 4.2.6, matching the bc.dockerfile.
