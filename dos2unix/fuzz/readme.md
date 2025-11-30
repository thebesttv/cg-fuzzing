# dos2unix Fuzzing Resources

This directory contains resources for fuzzing dos2unix using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with line ending characters
- `in/` - Initial input corpus (text files with various line endings)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created specifically for this project based on line ending patterns.

The initial input corpus contains text files with various line ending styles:
- `unix.txt` - Unix-style LF line endings
- `dos.txt` - DOS/Windows-style CRLF line endings
- `mixed.txt` - Mixed line endings
- `empty.txt` - Empty file
- `noeol.txt` - File without trailing newline
- `blanks.txt` - File with only blank lines

## Usage

Build the fuzzing Docker image:
```bash
docker build -f dos2unix/fuzz.dockerfile -t dos2unix-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm dos2unix-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm dos2unix-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: dos2unix CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Text files with various line ending styles
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses dos2unix version 7.5.2, matching the bc.dockerfile.
