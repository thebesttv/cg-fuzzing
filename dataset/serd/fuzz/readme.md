# serd Fuzzing Resources

This directory contains resources for fuzzing serd using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (RDF/Turtle syntax)
- `in/` - Initial input corpus (Turtle RDF files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary and input samples were created based on:
- Turtle/RDF specification: https://www.w3.org/TR/turtle/
- Serd documentation: https://drobilla.net/software/serd.html

## Usage

Build the fuzzing Docker image (from dataset directory):
```bash
cd dataset
docker build -f serd/fuzz.dockerfile -t serd-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm serd-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm serd-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: serdi CLI binary (RDF parser and serializer)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage
- **Input**: Turtle/RDF data files
- **Static linking**: For better performance

## Version

This fuzzing setup uses serd version 0.32.2, matching the bc.dockerfile.
