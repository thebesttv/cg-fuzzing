# aha Fuzzing Resources

This directory contains resources for fuzzing aha (ANSI to HTML converter) using AFL++.

## Files

- `dict` - Dictionary file containing ANSI escape sequences
- `in/` - Initial input corpus with various ANSI colored text samples
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file and input corpus were created specifically for this project, containing:
- Common ANSI escape sequences
- Color codes (foreground and background)
- Text styling codes (bold, underline, etc.)

## Usage

Build the fuzzing Docker image from the dataset directory:
```bash
cd dataset
docker build -f aha/fuzz.dockerfile -t aha-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm aha-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm aha-fuzz ./fuzz.sh -j 4
```

Monitor fuzzing progress (in another terminal):
```bash
docker exec -it <container_id> ./whatsup.sh
```

Or use watch mode:
```bash
docker exec -it <container_id> ./whatsup.sh -w
```

## Fuzzing Strategy

- **Target**: aha CLI binary (converts ANSI text from stdin or file)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of ANSI escape sequence parsing
- **Input**: Text files with various ANSI escape sequences
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses aha version 0.5.1, matching the bc.dockerfile.
