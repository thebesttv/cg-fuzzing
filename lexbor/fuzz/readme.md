# lexbor Fuzzing Resources

This directory contains resources for fuzzing lexbor HTML parser using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing with HTML keywords
- `in/` - Initial input corpus (HTML samples)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) contains HTML5 syntax keywords created for this project.
The initial input corpus contains basic HTML samples.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f lexbor/fuzz.dockerfile -t lexbor-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm lexbor-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm lexbor-fuzz ./fuzz.sh -j 4
```

Monitor fuzzing progress:
```bash
docker run -it --rm lexbor-fuzz ./whatsup.sh
```

## Fuzzing Strategy

- **Target**: lexbor_html_fuzz binary (HTML document parser fuzzer)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: HTML document data files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses lexbor version 2.6.0, matching the bc.dockerfile.
