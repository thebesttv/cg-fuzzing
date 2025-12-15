# Bchunk Fuzzing Resources

## External Resources

- **dict**: Custom dictionary created based on BIN/CUE format keywords
- **in/**: Sample CUE and BIN files for CD image conversion testing

## Project Information

- **Project**: bchunk - BIN/CUE CD image format converter
- **Version**: 1.2.2
- **Source**: http://he.fi/bchunk/bchunk-1.2.2.tar.gz
- **Build System**: Makefile

## Usage

```bash
cd dataset
docker build -f bchunk/fuzz.dockerfile -t bchunk-fuzz .
docker run -it --rm bchunk-fuzz
```

Inside the container, you can use:
- `/work/bin-fuzz` - AFL++ fuzzing binary
- `/work/bin-cmplog` - AFL++ CMPLOG binary
- `/work/bin-cov` - LLVM coverage binary
- `/work/bin-uftrace` - uftrace profiling binary
- `/work/fuzz.sh` - Start fuzzing
- `/work/whatsup.sh` - Monitor fuzzing progress

## Fuzzing Target

Bchunk converts CD images from BIN/CUE format to ISO/CDR tracks. The fuzzer tests various CUE file inputs (the track index file) to find potential vulnerabilities in the format parser.
