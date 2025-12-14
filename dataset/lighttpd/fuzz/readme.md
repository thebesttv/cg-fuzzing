# lighttpd Fuzzing Resources

This directory contains resources for fuzzing lighttpd using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (lighttpd configuration keywords)
- `in/` - Initial input corpus (lighttpd configuration files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary and input corpus were created specifically for this project based on lighttpd configuration syntax.

## Usage

Build the fuzzing Docker image:
```bash
cd dataset
docker build -f lighttpd/fuzz.dockerfile -t lighttpd-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm lighttpd-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm lighttpd-fuzz ./fuzz.sh -j 4
```

Monitor fuzzing progress:
```bash
docker run -it --rm lighttpd-fuzz ./whatsup.sh -w
```

## Fuzzing Strategy

- **Target**: lighttpd binary with configuration testing mode (`-t` flag)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: lighttpd configuration files (`.conf`)
- **Static linking**: For better performance and reproducibility
- **Command**: `lighttpd -t -f <config_file>` tests configuration without starting server

## Version

This fuzzing setup uses lighttpd version 1.4.82, matching the bc.dockerfile.
