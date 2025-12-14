# monocypher Fuzzing Resources

## Project Information
- **Project**: Monocypher (Cryptography Library)
- **Version**: 4.0.2
- **Source**: https://monocypher.org

## External Resources

- dict: Custom dictionary for crypto fuzzing (common patterns, edge cases)
- in/: Binary seed inputs for crypto testing

## Fuzzing Target

The fuzzing target exercises the Monocypher crypto API:
- Tests `crypto_blake2b()` hash function
- Tests `crypto_chacha20_h()` cipher
- Uses AFL persistent mode for performance

## Usage

```bash
cd dataset
docker build -f monocypher/fuzz.dockerfile -t monocypher-fuzz .
docker run -it --rm monocypher-fuzz
```

In the container, use:
- `/work/bin-fuzz` - AFL++ fuzzing binary
- `/work/bin-cmplog` - AFL++ CMPLOG binary
- `/work/bin-cov` - LLVM coverage binary
- `/work/bin-uftrace` - uftrace profiling binary
- `/work/fuzz.sh` - Start fuzzing
- `/work/whatsup.sh` - Monitor fuzzing progress

## Example Commands

```bash
# Start fuzzing with 1 core (interactive)
./fuzz.sh

# Start fuzzing with 4 cores (background)
./fuzz.sh -j 4

# Monitor progress
./whatsup.sh

# Watch progress (auto-refresh)
./whatsup.sh -w
```
