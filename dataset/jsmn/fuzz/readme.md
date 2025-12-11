# jsmn Fuzzing Resources

This directory contains resources for fuzzing jsmn (a minimalistic JSON parser) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (JSON tokens)
- `in/` - Initial input corpus (JSON files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) contains common JSON tokens and escape sequences.

The initial input corpus contains basic JSON samples created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f jsmn/fuzz.dockerfile -t jsmn-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm jsmn-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm jsmn-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: jsondump binary (reads JSON from file and dumps parsed tokens)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: JSON data files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses jsmn version 1.1.0, matching the bc.dockerfile.
