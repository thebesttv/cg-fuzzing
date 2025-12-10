# BearSSL Fuzzing Resources

## External Resources

- dict: Custom dictionary based on TLS/SSL and crypto terminology
- in/: Sample certificate and key files created for this project

## Usage

Build the fuzzing Docker image:
```bash
docker build -f bearssl/fuzz.dockerfile -t bearssl-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm bearssl-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm bearssl-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: brssl binary (BearSSL command-line tool)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Hash operation on input files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses BearSSL version 0.6, matching the bc.dockerfile.
