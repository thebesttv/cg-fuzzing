# xdelta3 Fuzzing Resources

## Project Info
- **Project**: xdelta3 - Binary delta compression tool
- **Source**: https://github.com/jmacd/xdelta
- **Version**: v3.1.0

## Fuzzing Resources

### Dictionary
- `dict`: Custom dictionary with VCDIFF format markers and xdelta3-specific patterns
- Includes magic numbers, instruction codes, and variable-length integers

### Input Corpus
- `in/`: Sample binary and delta files
  - Text files
  - Zero-filled blocks
  - Random data
  - VCDIFF magic headers

### Scripts
- `fuzz.sh`: Start AFL++ fuzzing with parallel support
- `whatsup.sh`: Monitor fuzzing progress

## Target Binary
We fuzz **xdelta3 decode** mode as it processes delta files, which is the most interesting attack surface.

## Usage

```bash
docker build -f xdelta/fuzz.dockerfile -t xdelta-fuzz .
docker run -it --rm xdelta-fuzz ./fuzz.sh
```

For parallel fuzzing:
```bash
docker run -it --rm xdelta-fuzz ./fuzz.sh -j 4
```
