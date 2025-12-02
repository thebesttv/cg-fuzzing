# odt2txt Fuzzing Resources

This directory contains resources for fuzzing odt2txt using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (ODT/OpenDocument format tokens)
- `in/` - Initial input corpus (ODT files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on:
- OpenDocument Format (ODF) specification
- ODT file structure (ZIP containing XML)
- Common XML elements and namespaces

The initial input corpus contains:
- `minimal.odt` - Minimal valid ODT with text
- `empty.odt` - ODT with empty paragraph
- `unicode.odt` - ODT with Unicode characters
- `special.odt` - ODT with special characters
- `corrupted.odt` - Incomplete ODT (only mimetype)

## Usage

Build the fuzzing Docker image:
```bash
docker build -f odt2txt/fuzz.dockerfile -t odt2txt-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm odt2txt-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm odt2txt-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: odt2txt CLI binary (converts ODT to plain text)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: ODT (OpenDocument Text) files
- **Note**: ODT files are ZIP archives containing XML

## Version

This fuzzing setup uses odt2txt version 0.5, matching the bc.dockerfile.
