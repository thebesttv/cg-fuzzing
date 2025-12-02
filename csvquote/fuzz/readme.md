# csvquote Fuzzing Resources

csvquote is a tool for handling CSV files with embedded commas and newlines.

## Target Binary

- `csvquote` - Process CSV files by replacing special characters

## External Resources

- dict: Created based on CSV format specification
- in/: Sample CSV files created for fuzzing

## Usage

Build the fuzzing Docker image:
```bash
docker build -f csvquote/fuzz.dockerfile -t csvquote-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm csvquote-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm csvquote-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: csvquote CLI binary
- **Instrumentation**: afl-clang-lto (collision-free)
- **CMPLOG**: Enabled for better coverage
- **Input**: CSV format files
- **Static linking**: For better performance

## Version

This fuzzing setup uses csvquote version 0.1.5, matching the bc.dockerfile.
