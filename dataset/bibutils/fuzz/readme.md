# bibutils Fuzzing Resources

This directory contains resources for fuzzing bibutils (bib2xml) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (BibTeX keywords)
- `in/` - Initial input corpus (sample BibTeX files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

- Dictionary: Created based on BibTeX format keywords
- Input corpus: Sample BibTeX files created for this project

## Usage

Build the fuzzing Docker image:
```bash
cd dataset
docker build -f bibutils/fuzz.dockerfile -t bibutils-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm bibutils-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm bibutils-fuzz ./fuzz.sh -j 4
```

Monitor fuzzing progress:
```bash
docker run -it --rm bibutils-fuzz ./whatsup.sh
```

## Fuzzing Strategy

- **Target**: bib2xml CLI binary (BibTeX to XML converter, same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: BibTeX bibliography files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses bibutils version 7.2, matching the bc.dockerfile.
