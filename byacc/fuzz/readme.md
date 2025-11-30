# byacc Fuzzing Resources

This directory contains resources for fuzzing byacc (Berkeley yacc) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with yacc grammar keywords
- `in/` - Initial input corpus (yacc grammar files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created specifically for this project based on yacc grammar syntax.

The initial input corpus contains basic yacc grammar samples created for this project:
- `simple.y` - Minimal grammar with a single token
- `calc.y` - Simple calculator grammar with precedence
- `minimal.y` - Minimalist grammar
- `union.y` - Grammar with %union and semantic actions
- `error.y` - Grammar with error recovery

## Usage

Build the fuzzing Docker image:
```bash
docker build -f byacc/fuzz.dockerfile -t byacc-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm byacc-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm byacc-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: byacc CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: yacc grammar files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses byacc version 20240109, matching the bc.dockerfile.
