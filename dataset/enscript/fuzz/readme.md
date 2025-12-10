# GNU enscript Fuzzing Resources

This directory contains resources for fuzzing GNU enscript using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with PostScript keywords
- `in/` - Initial input corpus (text files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) contains PostScript and text formatting keywords created for this project.

The initial input corpus contains basic text samples created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f enscript/fuzz.dockerfile -t enscript-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm enscript-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm enscript-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: enscript CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Text files to convert to PostScript
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses GNU enscript version 1.6.6, matching the bc.dockerfile.
