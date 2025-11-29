# mpc Fuzzing Resources

This directory contains resources for fuzzing mpc (parser combinator library) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with math expression tokens
- `in/` - Initial input corpus (math expression files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on the maths grammar defined in mpc's examples.

The initial input corpus contains basic math expressions created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f mpc/fuzz.dockerfile -t mpc-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm mpc-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm mpc-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: maths example binary (parses mathematical expressions)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Text files with mathematical expressions
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses mpc version 0.9.0, matching the bc.dockerfile.
