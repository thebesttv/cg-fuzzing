# dmidecode Fuzzing Resources

This directory contains resources for fuzzing dmidecode using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (DMI/SMBIOS keywords)
- `in/` - Initial input corpus (DMI dump files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

- Dictionary: Created based on DMI/SMBIOS specification keywords
- Input corpus: Minimal SMBIOS entry point structures created for this project

## Usage

Build the fuzzing Docker image:
```bash
cd dataset
docker build -f dmidecode/fuzz.dockerfile -t dmidecode-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm dmidecode-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm dmidecode-fuzz ./fuzz.sh -j 4
```

Monitor fuzzing progress:
```bash
docker run -it --rm dmidecode-fuzz ./whatsup.sh
```

## Fuzzing Strategy

- **Target**: dmidecode CLI binary with `--from-dump` option (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: DMI/SMBIOS binary dump files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses dmidecode version 3.6, matching the bc.dockerfile.
