# mpg123 Fuzzing Resources

This directory contains resources for fuzzing mpg123 using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (MP3/MPEG audio keywords)
- `in/` - Initial input corpus (minimal MP3 files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) is custom-created based on:
- MP3/MPEG frame structure
- ID3v1 and ID3v2 tag formats
- Common bitrates and sample rates
- VBR headers (Xing, Info, LAME)

The initial input corpus contains minimal valid MP3 frames and ID3 tags created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f mpg123/fuzz.dockerfile -t mpg123-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm mpg123-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm mpg123-fuzz ./fuzz.sh -j 4
```

Monitor fuzzing progress (in another terminal):
```bash
docker exec -it <container_id> ./whatsup.sh
# or watch mode:
docker exec -it <container_id> ./whatsup.sh -w
```

## Fuzzing Strategy

- **Target**: mpg123 CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: MP3 files processed with `-t` (test/decode mode)
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses mpg123 version 1.32.7, matching the bc.dockerfile.
