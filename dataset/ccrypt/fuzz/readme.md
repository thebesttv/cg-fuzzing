# ccrypt Fuzzing Resources

This directory contains resources for fuzzing ccrypt using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (ccrypt command-line options)
- `in/` - Initial input corpus (sample text files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

- Dictionary and input corpus created specifically for ccrypt

## Usage

Build the fuzzing Docker image:
```bash
cd dataset
docker build -f ccrypt/fuzz.dockerfile -t ccrypt-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm ccrypt-fuzz
./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm ccrypt-fuzz
./fuzz.sh -j 4
```

Monitor fuzzing progress:
```bash
./whatsup.sh
```

## Fuzzing Strategy

- **Target**: ccrypt CLI binary (file encryption tool)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Text files encrypted with -c option
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses ccrypt version 1.11, matching the bc.dockerfile.
