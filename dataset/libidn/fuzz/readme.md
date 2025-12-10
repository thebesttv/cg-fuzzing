# libidn Fuzzing Resources

This directory contains resources for fuzzing libidn (Internationalized Domain Names library) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (IDN and Unicode related tokens)
- `in/` - Initial input corpus (domain name examples)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created for this project based on:
- Common domain name patterns
- Punycode prefix (xn--)
- Unicode characters from various scripts
- IDN processing keywords

The initial input corpus contains:
- `simple.txt` - Simple ASCII domain
- `german.txt` - German umlaut domain
- `punycode.txt` - Punycode encoded domain
- `japanese.txt` - Japanese domain
- `subdomain.txt` - Multi-level subdomain

## Usage

Build the fuzzing Docker image:
```bash
docker build -f libidn/fuzz.dockerfile -t libidn-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm libidn-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm libidn-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: idn binary (IDN domain name converter)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Domain names with international characters
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses libidn version 1.42, matching the bc.dockerfile.
