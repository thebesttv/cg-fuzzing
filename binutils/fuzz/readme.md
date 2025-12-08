# binutils Fuzzing Resources

## External Resources

- dict: Custom created ELF format dictionary
- in/: Generated ELF binaries (executables, objects, libraries)

## Usage

```bash
docker build -f binutils/fuzz.dockerfile -t binutils-fuzz .
docker run -it --rm binutils-fuzz ./fuzz.sh
```

## Fuzzing binutils

binutils is a collection of binary tools for manipulating object files. The fuzzing targets `readelf` which:
- Parses ELF file format
- Displays information about ELF files
- Handles various ELF sections and segments

The fuzzer uses `-a @@` to:
- `-a`: Display all information (exercises full parsing)
- `@@`: Input file placeholder for AFL++
