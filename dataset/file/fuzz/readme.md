# file (libmagic) Fuzzing Resources

This directory contains resources for fuzzing the file command using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with magic signatures and patterns
- `in/` - Initial input corpus (various file type samples)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on common file magic signatures, including:
- Executable formats (ELF, PE, Mach-O)
- Archive formats (ZIP, gzip, bzip2, xz)
- Document formats (PDF, Office)
- Image formats (PNG, JPEG, GIF, WEBP)
- Text patterns (shebang, XML, HTML)

The initial input corpus contains various file type samples:
- Text files (text.txt)
- Shell scripts (script.sh)
- XML documents (doc.xml)
- HTML pages (page.html)
- ELF headers (elf32.bin)
- PNG headers (image.png)
- Gzip headers (compressed.gz)
- ZIP headers (archive.zip)

## Usage

Build the fuzzing Docker image:
```bash
docker build -f file/fuzz.dockerfile -t file-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm file-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm file-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: file CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Various file types with magic signatures
- **Static linking**: For better performance and reproducibility
- **Options**: `-m magic.mgc` to use bundled magic database

## Version

This fuzzing setup uses file version 5.46, matching the bc.dockerfile.
