# sox Fuzzing Resources

This directory contains resources for fuzzing SoX (Sound eXchange) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (audio format keywords)
- `in/` - Initial input corpus (minimal audio files: WAV, AU, raw PCM)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) is custom-created based on:
- WAV/RIFF format specifications
- AIFF/AIFC format specifications
- AU/SND (Sun/NeXT) format
- Common audio parameters (sample rates, bit depths, channels)

The initial input corpus contains minimal valid audio files created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f sox/fuzz.dockerfile -t sox-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm sox-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm sox-fuzz ./fuzz.sh -j 4
```

Monitor fuzzing progress (in another terminal):
```bash
docker exec -it <container_id> ./whatsup.sh
# or watch mode:
docker exec -it <container_id> ./whatsup.sh -w
```

## Fuzzing Strategy

- **Target**: sox CLI binary (same binary as used for WLLVM/bitcode extraction)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Audio files processed with `-n /dev/null` (no output, just parsing/processing)
- **Static linking**: For better performance and reproducibility
- **Format support**: Built-in formats only (no external codec libraries)

## Version

This fuzzing setup uses SoX version 14.4.2, matching the bc.dockerfile.
