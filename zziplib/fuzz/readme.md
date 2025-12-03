# zziplib Fuzzing Resources

## Project Info
- **Project**: zziplib - ZIP file access library
- **Source**: https://github.com/gdraheim/zziplib
- **Version**: v0.13.80

## Fuzzing Resources

### Dictionary
- `dict`: Custom dictionary with ZIP file format signatures and patterns
- Includes magic numbers, compression methods, and common structures

### Input Corpus
- `in/`: Sample ZIP files
  - Valid ZIP archives
  - Corrupted ZIP headers
  - Random data

### Scripts
- `fuzz.sh`: Start AFL++ fuzzing with parallel support
- `whatsup.sh`: Monitor fuzzing progress

## Target Binary
We fuzz **unzip-mem** which processes ZIP files entirely in memory, a good attack surface for parsing bugs.

## Usage

```bash
docker build -f zziplib/fuzz.dockerfile -t zziplib-fuzz .
docker run -it --rm zziplib-fuzz ./fuzz.sh
```

For parallel fuzzing:
```bash
docker run -it --rm zziplib-fuzz ./fuzz.sh -j 4
```
