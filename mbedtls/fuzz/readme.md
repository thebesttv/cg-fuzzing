# mbedtls Fuzzing Resources

This directory contains resources for fuzzing mbedTLS cryptography library using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (PEM/DER format tokens)
- `in/` - Initial input corpus (PEM keys and certificates)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

- dict: Custom dictionary based on PEM/DER formats and cryptographic identifiers
- in/: Minimal PEM key/certificate samples created for this project

## Usage

Build the fuzzing Docker image:
```bash
docker build -f mbedtls/fuzz.dockerfile -t mbedtls-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm mbedtls-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm mbedtls-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: pk_decrypt CLI utility (reads private key file)
- **Instrumentation**: afl-clang-fast (AFL++ instrumentation)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: PEM-encoded private keys and certificates
- **Note**: Key parsing is the primary fuzzing target

## Version

This fuzzing setup uses mbedTLS version 3.6.2, matching the bc.dockerfile.
