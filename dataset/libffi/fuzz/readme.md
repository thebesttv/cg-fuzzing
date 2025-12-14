# libffi Fuzzing Resources

## Project Information
- **Project**: libffi (Foreign Function Interface Library)
- **Version**: 3.4.6
- **Source**: https://github.com/libffi/libffi

## External Resources

- dict: Custom dictionary for FFI fuzzing (type indicators and common values)
- in/: Custom seed inputs for FFI call fuzzing

## Fuzzing Target

The fuzzing target is a custom harness that exercises the libffi API:
- Tests `ffi_prep_cif()` with various argument configurations
- Tests `ffi_call()` with different function signatures
- Uses AFL persistent mode for performance

## Usage

```bash
cd dataset
docker build -f libffi/fuzz.dockerfile -t libffi-fuzz .
docker run -it --rm libffi-fuzz
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
