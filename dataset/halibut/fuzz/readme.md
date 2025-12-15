# Halibut Fuzzing Resources

This directory contains resources for fuzzing halibut using AFL++.

## Files

- `dict` - Dictionary file with halibut document format keywords
- `in/` - Initial input corpus (halibut .but documents)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary and input corpus were created specifically for this project based on halibut's document format specification.

## Usage

Build the fuzzing Docker image:
```bash
cd dataset
docker build -f halibut/fuzz.dockerfile -t halibut-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm halibut-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm halibut-fuzz ./fuzz.sh -j 4
```

Monitor fuzzing progress:
```bash
docker run -it --rm halibut-fuzz ./whatsup.sh
```

## Fuzzing Strategy

- **Target**: halibut CLI binary (document converter)
- **Input**: halibut .but format documents
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses halibut version 1.3, matching the bc.dockerfile.
