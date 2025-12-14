# harfbuzz Fuzzing Resources

## Project Information
- **Project**: HarfBuzz (Text Shaping Library)
- **Version**: 10.1.0
- **Source**: https://github.com/harfbuzz/harfbuzz

## External Resources

- dict: Custom dictionary for font format fuzzing (TrueType/OpenType tags and magic numbers)
- in/: Minimal font file seeds (TTF/TTC format headers)

## Fuzzing Target

The fuzzing target exercises the HarfBuzz shaping API:
- Tests `hb_face_create()` with various font data
- Tests `hb_shape()` for text shaping
- Uses AFL persistent mode for performance

## Usage

```bash
cd dataset
docker build -f harfbuzz/fuzz.dockerfile -t harfbuzz-fuzz .
docker run -it --rm harfbuzz-fuzz
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
