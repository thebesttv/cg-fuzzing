# llhttp Fuzzing Resources

## External Resources

- dict: Custom dictionary based on HTTP/1.1 specification (RFC 7230-7235)
- in/: Sample HTTP requests and responses created for this project

## Usage

Build the fuzzing Docker image:
```bash
docker build -f llhttp/fuzz.dockerfile -t llhttp-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm llhttp-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm llhttp-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: llhttp_harness binary (parses HTTP requests/responses)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: HTTP request/response data files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses llhttp version 9.2.1, matching the bc.dockerfile.
