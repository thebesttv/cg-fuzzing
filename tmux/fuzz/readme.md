# tmux Fuzzing Resources

This directory contains resources for fuzzing tmux using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (tmux config syntax)
- `in/` - Initial input corpus (tmux configuration files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) is created based on tmux configuration file syntax and commands.
The initial input corpus contains basic tmux configuration file samples.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f tmux/fuzz.dockerfile -t tmux-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm tmux-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm tmux-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: tmux CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: tmux configuration files parsed with `tmux -f <input> -C`
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses tmux version 3.6, matching the bc.dockerfile.
