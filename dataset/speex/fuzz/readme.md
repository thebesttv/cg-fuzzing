# speex Fuzzing Resources

This directory contains resources for fuzzing Speex audio codec using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (Speex/Ogg format tokens)
- `in/` - Initial input corpus (Speex/Ogg files and audio samples)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

- dict: Custom dictionary based on Speex file format and Ogg container
- in/: Minimal Speex/Ogg files created for this project

## Usage

Build the fuzzing Docker image:
```bash
docker build -f speex/fuzz.dockerfile -t speex-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm speex-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm speex-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: speexdec CLI binary (decodes Speex audio to WAV)
- **Instrumentation**: afl-clang-fast (AFL++ instrumentation)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Speex/Ogg container files
- **Output**: Decoded to /dev/null (no file write)

## Version

This fuzzing setup uses Speex version 1.2.1, matching the bc.dockerfile.
