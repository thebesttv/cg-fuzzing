# tinyexpr Fuzzing Resources

tinyexpr is a tiny recursive descent expression parser and evaluator.

## Target Binary

- `repl` - REPL (Read-Eval-Print-Loop) for evaluating mathematical expressions

## External Resources

- dict: Created based on tinyexpr supported operators and functions
- in/: Sample expression files created for fuzzing

## Usage

Build the fuzzing Docker image:
```bash
docker build -f tinyexpr/fuzz.dockerfile -t tinyexpr-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm tinyexpr-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm tinyexpr-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: tinyexpr REPL binary
- **Instrumentation**: afl-clang-lto (collision-free)
- **CMPLOG**: Enabled for better coverage
- **Input**: Mathematical expression strings
- **Static linking**: For better performance

## Version

This fuzzing setup uses tinyexpr master branch, matching the bc.dockerfile.
