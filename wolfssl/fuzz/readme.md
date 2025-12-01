# wolfSSL Fuzzing Resources

## External Resources

- dict: Custom dictionary based on ASN.1/DER and crypto terminology
- in/: Sample DER/PEM files created for this project

## Usage

Build the fuzzing Docker image:
```bash
docker build -f wolfssl/fuzz.dockerfile -t wolfssl-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm wolfssl-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm wolfssl-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: asn1 binary (ASN.1/DER parser)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: DER/PEM encoded files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses wolfSSL version 5.7.4, matching the bc.dockerfile.
