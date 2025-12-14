# nanosvg Fuzzing Resources

## Project Information
- **Project**: NanoSVG (SVG Parser)
- **Version**: master
- **Source**: https://github.com/memononen/nanosvg

## External Resources

- dict: Custom dictionary for SVG fuzzing (tags, attributes, values)
- in/: Minimal SVG seed inputs

## Fuzzing Target

The fuzzing target exercises the NanoSVG parsing API:
- Tests `nsvgParse()` with various SVG inputs
- Header-only library implementation
- Uses AFL persistent mode for performance

## Usage

```bash
cd dataset
docker build -f nanosvg/fuzz.dockerfile -t nanosvg-fuzz .
docker run -it --rm nanosvg-fuzz
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
