# expat (xmlwf) Fuzzing Resources

This directory contains resources for fuzzing expat XML parser (xmlwf tool) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with XML keywords and syntax
- `in/` - Initial input corpus (XML files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) contains XML syntax tokens, keywords and special sequences
commonly used in XML documents.

The initial input corpus contains basic valid XML documents created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f expat/fuzz.dockerfile -t expat-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm expat-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm expat-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: xmlwf CLI binary (XML Well-Formedness checker)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: XML files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses expat version 2.7.3, matching the bc.dockerfile.
