# figlet Fuzzing Resources

## About figlet

FIGlet (Frank, Ian & Glenn's letters) is a program that creates large characters out of ordinary screen characters. It reads text from stdin and outputs ASCII art representations.

## External Resources

- dict: Created for this project based on common text patterns
- in/: Created for this project with sample text inputs

## Usage

Build the fuzzing Docker image:
```bash
docker build -f figlet/fuzz.dockerfile -t figlet-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm figlet-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm figlet-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: figlet CLI binary (reads from stdin)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Text strings for ASCII art rendering
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses figlet version 2.2.5.
