# wavpack Fuzzing Resources

## Project Info
- **Project**: WavPack - Hybrid lossless audio compression
- **Source**: https://github.com/dbry/WavPack
- **Version**: 5.8.1

## Fuzzing Resources

### Dictionary
- `dict`: Custom dictionary with WavPack and WAVE format patterns

### Input Corpus
- `in/`: Sample WavPack files
  - WavPack headers
  - Random data
  - Binary samples

### Scripts
- `fuzz.sh`: Start AFL++ fuzzing with parallel support
- `whatsup.sh`: Monitor fuzzing progress

## Target Binary
We fuzz **wvunpack** which decodes WavPack files.

## Usage

```bash
docker build -f wavpack/fuzz.dockerfile -t wavpack-fuzz .
docker run -it --rm wavpack-fuzz ./fuzz.sh
```

For parallel fuzzing:
```bash
docker run -it --rm wavpack-fuzz ./fuzz.sh -j 4
```
