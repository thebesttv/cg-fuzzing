# html-xml-utils Fuzzing Resources

This directory contains resources for fuzzing hxnormalize using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (HTML/XML tags and attributes)
- `in/` - Initial input corpus (HTML files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

- dict: Custom dictionary based on HTML/XML syntax
- in/: Sample HTML files for initial corpus

## Usage

Build the fuzzing Docker image:
```bash
docker build -f html-xml-utils/fuzz.dockerfile -t html-xml-utils-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm html-xml-utils-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm html-xml-utils-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: hxnormalize CLI binary (HTML normalizer/pretty-printer)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: HTML/XML files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses html-xml-utils version 8.6, matching the bc.dockerfile.
