# jimtcl Fuzzing Resources

This directory contains resources for fuzzing jimtcl (Jim Tcl interpreter) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with Tcl keywords
- `in/` - Initial input corpus (Tcl script files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) was created based on Tcl language keywords and operators.

The initial input corpus contains basic Tcl script samples created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f jimtcl/fuzz.dockerfile -t jimtcl-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm jimtcl-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm jimtcl-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: jimsh CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Tcl script files executed by jimsh
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses jimtcl version 0.83, matching the bc.dockerfile.
