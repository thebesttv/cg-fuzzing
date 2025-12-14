# nginx Fuzzing Resources

This directory contains resources for fuzzing nginx using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (nginx configuration keywords)
- `in/` - Initial input corpus (nginx configuration files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary and input corpus were created specifically for this project based on nginx configuration syntax.

## Usage

Build the fuzzing Docker image:
```bash
cd dataset
docker build -f nginx/fuzz.dockerfile -t nginx-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm nginx-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm nginx-fuzz ./fuzz.sh -j 4
```

Monitor fuzzing progress:
```bash
docker run -it --rm nginx-fuzz ./whatsup.sh -w
```

## Fuzzing Strategy

- **Target**: nginx binary with configuration testing mode (`-t` flag)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: nginx configuration files (`.conf`)
- **Static linking**: For better performance and reproducibility
- **Command**: `nginx -t -c <config_file>` tests configuration without starting server

## Version

This fuzzing setup uses nginx version 1.29.4, matching the bc.dockerfile.
