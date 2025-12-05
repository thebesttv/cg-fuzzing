# rsync Fuzzing Resources

This directory contains resources for fuzzing rsync using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (rsync protocol keywords)
- `in/` - Initial input corpus (protocol messages, file lists, options)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) is custom-created based on:
- rsync protocol handshake messages
- Protocol version numbers
- Common option flags
- File attribute markers
- Delta encoding parameters

The initial input corpus contains:
- Daemon protocol handshake
- File list formats
- Exclude patterns
- Batch file markers
- Option strings

## Usage

Build the fuzzing Docker image:
```bash
docker build -f rsync/fuzz.dockerfile -t rsync-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm rsync-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm rsync-fuzz ./fuzz.sh -j 4
```

Monitor fuzzing progress (in another terminal):
```bash
docker exec -it <container_id> ./whatsup.sh
# or watch mode:
docker exec -it <container_id> ./whatsup.sh -w
```

## Fuzzing Strategy

- **Target**: rsync CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Fuzzing stdin input to --version (protocol parsing)
- **Static linking**: For better performance and reproducibility
- **Dependencies**: Built without xxhash, zstd, lz4, openssl for simpler dependencies

## Version

This fuzzing setup uses rsync version 3.3.0, matching the bc.dockerfile.
