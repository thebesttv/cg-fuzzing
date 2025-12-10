# jemalloc Fuzzing Resources

## External Resources

- dict: Created based on jemalloc API keywords and common allocation patterns
- in/: Self-created minimal test inputs for malloc test program

## Usage

```bash
docker build -f jemalloc/fuzz.dockerfile -t jemalloc-fuzz .
docker run -it --rm jemalloc-fuzz ./fuzz.sh
```

## Fuzzing Target

The fuzzing target is `test/integration/malloc`, a test program that exercises jemalloc's malloc implementation with various allocation patterns.
