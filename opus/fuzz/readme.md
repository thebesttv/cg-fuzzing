# opus Fuzzing Resources

This directory contains resources for fuzzing Opus audio codec using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (Opus format tokens)
- `in/` - Initial input corpus (PCM audio samples and Opus headers)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

- dict: Custom dictionary based on Opus format and command-line options
- in/: PCM audio samples created for this project

## Usage

Build the fuzzing Docker image:
```bash
docker build -f opus/fuzz.dockerfile -t opus-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm opus-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm opus-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: opus_demo CLI binary (encode mode with VoIP preset)
- **Instrumentation**: afl-clang-fast (AFL++ instrumentation)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: PCM audio samples (raw audio data)
- **Output**: Encoded to /dev/null (no file write)
- **Mode**: Encode mode (-e voip 48000 1 24000)

## Version

This fuzzing setup uses Opus version 1.5.2, matching the bc.dockerfile.
