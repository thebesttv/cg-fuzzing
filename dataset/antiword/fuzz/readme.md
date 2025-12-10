# antiword Fuzzing Resources

## About antiword

antiword is a free MS Word document reader that converts Word files to text, PostScript, or PDF formats.

## External Resources

- dict: Created for this project based on OLE compound file format and Word document structure
- in/: Created for this project with minimal DOC file headers

## Usage

Build the fuzzing Docker image:
```bash
docker build -f antiword/fuzz.dockerfile -t antiword-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm antiword-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm antiword-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: antiword CLI binary
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: MS Word .doc files (OLE compound file format)
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses the latest antiword from the main branch on GitHub.
