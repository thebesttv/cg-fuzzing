# lzip Fuzzing Resources

## Project Info
- **Project**: lzip - Lossless data compressor
- **Source**: http://www.nongnu.org/lzip/lzip.html
- **Version**: 1.15

## Fuzzing Resources

### Dictionary
- `dict`: Custom dictionary with lzip format patterns

### Input Corpus
- `in/`: Sample compressed files

### Scripts
- `fuzz.sh`: Start AFL++ fuzzing with parallel support
- `whatsup.sh`: Monitor fuzzing progress

## Target Binary
We fuzz **lzip** decompression mode.

## Usage

```bash
docker build -f lzip/fuzz.dockerfile -t lzip-fuzz .
docker run -it --rm lzip-fuzz ./fuzz.sh
```

For parallel fuzzing:
```bash
docker run -it --rm lzip-fuzz ./fuzz.sh -j 4
```
