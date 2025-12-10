# frozen JSON Parser Fuzzing Resources

This directory contains resources for fuzzing the frozen JSON parser using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing
- `in/` - Initial input corpus (JSON files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) is custom-created based on JSON syntax including:
- JSON structural characters
- Literals (true, false, null)
- String escapes
- Common keys

The initial input corpus contains sample JSON files:
- empty_object.json - Empty object `{}`
- empty_array.json - Empty array `[]`
- simple_object.json - Simple key-value object
- simple_array.json - Array of numbers
- nested.json - Nested object
- true.json, null.json - Literals
- number.json - Floating point number
- string.json - Simple string

## Usage

Build the fuzzing Docker image:
```bash
docker build -f frozen/fuzz.dockerfile -t frozen-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm frozen-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm frozen-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: Custom fuzz_json harness using frozen's json_walk and json_scanf APIs
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: JSON files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses frozen version 1.7, matching the bc.dockerfile.

## Note on Harness

Since frozen is a library without a CLI tool, a custom harness (`fuzz_json.c`) was created
that reads JSON from a file and parses it using frozen's API functions:
- json_scanf_array_elem() - For parsing array elements
- json_scanf() - For extracting specific values
- json_walk() - For callback-based JSON traversal
