# hello Fuzzing Resources

This directory contains resources for fuzzing GNU hello using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing
- `in/` - Initial input corpus
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file and input corpus are created for this project.
GNU hello is a simple demonstration program, mainly useful for testing 
fuzzing setup.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f hello/fuzz.dockerfile -t hello-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm hello-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm hello-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: hello CLI binary
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Greeting text via stdin
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses GNU hello version 2.12.1, matching the bc.dockerfile.
