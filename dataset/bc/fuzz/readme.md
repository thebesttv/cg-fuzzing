# GNU bc Fuzzing Resources

This directory contains resources for fuzzing GNU bc using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with bc language keywords
- `in/` - Initial input corpus (bc script files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on bc language specification, including:
- Arithmetic and comparison operators
- Built-in functions (sqrt, s, c, a, l, e, j)
- Control flow keywords (if, else, while, for)
- Variable handling (define, auto, scale, ibase, obase)

The initial input corpus contains various bc scripts:
- Simple arithmetic (simple1.bc)
- Pi calculation using arctangent (pi.bc)
- Recursive factorial function (factorial.bc)
- For loop example (loop.bc)
- Variable operations (vars.bc)
- Hexadecimal conversion (hex.bc)
- Square root calculation (sqrt.bc)
- If-else conditionals (ifelse.bc)

## Usage

Build the fuzzing Docker image:
```bash
docker build -f bc/fuzz.dockerfile -t bc-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm bc-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm bc-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: GNU bc CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: bc script files (mathematical expressions, functions, loops)
- **Static linking**: For better performance and reproducibility
- **Options**: `-q` for quiet mode (suppress banner)

## Version

This fuzzing setup uses GNU bc version 1.08.2, matching the bc.dockerfile.
