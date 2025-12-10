# recutils Fuzzing Resources

## About recutils

GNU recutils is a set of tools and libraries to access human-editable, plain text databases called recfiles.

## External Resources

- dict: Created for this project based on rec file format syntax
- in/: Created for this project with sample rec files

## Usage

Build the fuzzing Docker image:
```bash
docker build -f recutils/fuzz.dockerfile -t recutils-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm recutils-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm recutils-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: recsel CLI binary (reads and queries rec files)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: recfile database files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses recutils version 1.9.
