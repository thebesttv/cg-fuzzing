# tomlc99 Fuzzing Resources

This directory contains resources for fuzzing tomlc99 using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (TOML syntax tokens)
- `in/` - Initial input corpus (TOML files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on TOML specification tokens.

The initial input corpus contains sample TOML files covering various TOML features.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f tomlc99/fuzz.dockerfile -t tomlc99-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm tomlc99-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm tomlc99-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: toml_cat CLI binary (parses TOML file and outputs JSON)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: TOML data files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses tomlc99 from master branch.
