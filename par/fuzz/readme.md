# par Fuzzing Resources

## About par

par is a paragraph reformatter, similar to fmt but with more features. It reads text from stdin and reformats it to fit within a specified column width.

## External Resources

- dict: Created for this project based on text formatting patterns
- in/: Created for this project with sample text files

## Usage

Build the fuzzing Docker image:
```bash
docker build -f par/fuzz.dockerfile -t par-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm par-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm par-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: par CLI binary (reads from stdin)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Text files for paragraph reformatting
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses par version 1.53.0.
