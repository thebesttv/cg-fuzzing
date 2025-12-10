# squashfs-tools Fuzzing Resources

This directory contains resources for fuzzing squashfs-tools (unsquashfs) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing
- `in/` - Initial input corpus (squashfs images)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) is custom-created based on squashfs file format structures including:
- Magic numbers (hsqs, sqsh, shsq, qshs)
- Compression type identifiers
- Block size values
- Inode type identifiers

The initial input corpus contains minimal squashfs images:
- minimal.sqsh - Minimal squashfs v4 superblock

## Usage

Build the fuzzing Docker image:
```bash
docker build -f squashfs-tools/fuzz.dockerfile -t squashfs-tools-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm squashfs-tools-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm squashfs-tools-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: unsquashfs CLI binary with `-l` flag (list mode - doesn't extract files)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: squashfs filesystem images
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses squashfs-tools version 4.7.4, matching the bc.dockerfile.
