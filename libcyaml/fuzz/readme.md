# libcyaml Fuzzing Resources

This directory contains resources for fuzzing libcyaml using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing containing YAML-related tokens
- `in/` - Initial input corpus (YAML samples)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created for this project, containing:
- YAML syntax elements (colons, dashes, brackets)
- Common YAML values (true, false, null)
- Special YAML indicators (---, ...)

The initial input corpus contains YAML samples matching the numerical example format.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f libcyaml/fuzz.dockerfile -t libcyaml-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm libcyaml-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm libcyaml-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: numerical CLI tool (parses YAML using libcyaml)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: YAML files processed by the numerical example
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses libcyaml version 1.4.2, matching the bc.dockerfile.
