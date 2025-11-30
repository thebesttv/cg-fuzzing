# libsndfile Fuzzing Resources

This directory contains resources for fuzzing libsndfile using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing
- `in/` - Initial input corpus (audio files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) is custom-created based on audio file format headers and common structures.

The initial input corpus contains minimal valid audio file samples created for this project:
- minimal.wav - Minimal WAV file (44 bytes header + 8 bytes data)
- minimal.aiff - Minimal AIFF file
- minimal.au - Minimal AU/SND file
- minimal.caf - Minimal CAF file

## Usage

Build the fuzzing Docker image:
```bash
docker build -f libsndfile/fuzz.dockerfile -t libsndfile-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm libsndfile-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm libsndfile-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: sndfile-info CLI binary (reads and parses audio files)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Audio files (WAV, AIFF, AU, CAF, etc.)
- **Static linking**: For better performance and reproducibility
- **External libs**: Disabled (FLAC, Ogg, Vorbis, Opus, MPEG) to simplify static linking

## Version

This fuzzing setup uses libsndfile version 1.2.2, matching the bc.dockerfile.
