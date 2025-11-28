# git Fuzzing Resources

This directory contains resources for fuzzing git using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (git config syntax)
- `in/` - Initial input corpus (git config files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) is created based on git config file syntax.
The initial input corpus contains basic git configuration file samples.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f git/fuzz.dockerfile -t git-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm git-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm git-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: git CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Git configuration files parsed with `git config --file <input> --list`
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses git version 2.52.0, matching the bc.dockerfile.
