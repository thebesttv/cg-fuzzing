# Lua Fuzzing Resources

This directory contains resources for fuzzing Lua using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (Lua keywords and syntax)
- `in/` - Initial input corpus (Lua scripts)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on the Lua 5.4 language reference:
- Source: https://www.lua.org/manual/5.4/manual.html

The initial input corpus contains basic Lua script samples created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f lua/fuzz.dockerfile -t lua-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm lua-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm lua-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: lua CLI interpreter (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Lua script files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses Lua version 5.4.8, matching the bc.dockerfile.
