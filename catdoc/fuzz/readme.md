# catdoc Fuzzing Resources

This directory contains resources for fuzzing catdoc (Microsoft Word document parser) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with DOC file format patterns
- `in/` - Initial input corpus (DOC files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created specifically for this project based on OLE2 compound document format and Word document structure.

The initial input corpus contains:
- `minimal.doc` - Minimal OLE2 header structure
- `empty.doc` - Empty file
- `random.doc` - Random binary data

## Usage

Build the fuzzing Docker image:
```bash
docker build -f catdoc/fuzz.dockerfile -t catdoc-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm catdoc-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm catdoc-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: catdoc CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Microsoft Word DOC files (OLE2 compound document format)
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses catdoc version 0.95, matching the bc.dockerfile.
