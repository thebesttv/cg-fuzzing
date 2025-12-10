# parson Fuzzing Resources

This directory contains resources for fuzzing parson using AFL++.

## Files

- `harness.c` - Simple harness that uses parson's json_parse_file() function
- `dict` - Dictionary file for AFL++ fuzzing (JSON tokens)
- `in/` - Initial input corpus (JSON files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) contains common JSON tokens based on the JSON specification.

The initial input corpus contains basic JSON samples created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f parson/fuzz.dockerfile -t parson-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm parson-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm parson-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: parson_harness binary (calls json_parse_file from parson library)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: JSON data files passed as command line argument
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses parson version 1.5.3 (commit ba29f4e), matching the bc.dockerfile.
