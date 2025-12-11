# less Fuzzing Resources

This directory contains resources for fuzzing less using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (less commands and options)
- `in/` - Initial input corpus (text files with various content)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on:
- less manual page and documentation
- Common less commands and key bindings

The initial input corpus contains:
- Plain text files
- Files with special characters (tabs, newlines, ANSI codes)
- Edge cases (empty files, long lines)

## Usage

Build the fuzzing Docker image:
```bash
docker build -f less/fuzz.dockerfile -t less-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm less-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm less-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: less CLI binary (file reading mode with `-f` flag)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Text files with various content
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses less version 668, matching the bc.dockerfile.
