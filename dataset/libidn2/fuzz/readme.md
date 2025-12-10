# libidn2 Fuzzing Resources

This directory contains resources for fuzzing libidn2 (idn2 CLI) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (IDN/Punycode keywords)
- `in/` - Initial input corpus (domain names with international characters)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) contains IDN/Punycode specific keywords such as:
- Punycode prefixes (xn--)
- Common TLDs
- International domain name examples
- Command line options

The initial input corpus contains sample domain names in various scripts.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f libidn2/fuzz.dockerfile -t libidn2-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm libidn2-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm libidn2-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: idn2 CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Domain names read from file for IDNA conversion
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses libidn2 version 2.3.8, matching the bc.dockerfile.
