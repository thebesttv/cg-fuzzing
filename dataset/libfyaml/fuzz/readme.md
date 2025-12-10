# libfyaml Fuzzing Resources

This directory contains resources for fuzzing libfyaml using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with YAML keywords
- `in/` - Initial input corpus (YAML files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) contains YAML syntax keywords created for this project.

The initial input corpus contains basic YAML samples created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f libfyaml/fuzz.dockerfile -t libfyaml-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm libfyaml-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm libfyaml-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: fy-tool CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: YAML data files processed with --dump option
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses libfyaml version 0.9, matching the bc.dockerfile.
