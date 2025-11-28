# mruby Fuzzing Resources

This directory contains resources for fuzzing mruby Ruby interpreter using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (Ruby syntax tokens)
- `in/` - Initial input corpus (Ruby files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on Ruby language specification tokens.

The initial input corpus contains sample Ruby files covering various Ruby features.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f mruby/fuzz.dockerfile -t mruby-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm mruby-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm mruby-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: mruby CLI binary (executes Ruby files)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Ruby source files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses mruby version 3.4.0.
