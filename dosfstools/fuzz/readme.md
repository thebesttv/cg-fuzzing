# dosfstools Fuzzing Resources

This directory contains resources for fuzzing dosfstools using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing containing FAT filesystem tokens
- `in/` - Initial input corpus (FAT filesystem samples)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created for this project, containing:
- FAT filesystem magic bytes
- Boot sector signatures
- Common FAT values and headers

The initial input corpus contains basic FAT image samples created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f dosfstools/fuzz.dockerfile -t dosfstools-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm dosfstools-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm dosfstools-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: fsck.fat CLI tool (checks FAT filesystem images)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: FAT filesystem image files processed in check-only mode (-n)
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses dosfstools version 4.2, matching the bc.dockerfile.
