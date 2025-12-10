# yajl Fuzzing Resources

This directory contains resources for fuzzing yajl (json_verify) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (JSON syntax tokens)
- `in/` - Initial input corpus (JSON files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) is based on the json.dict from AFL++:
- Source: https://github.com/AFLplusplus/AFLplusplus/blob/stable/dictionaries/json.dict
- Extended with additional JSON tokens for better coverage

The initial input corpus contains basic JSON samples created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f yajl/fuzz.dockerfile -t yajl-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm yajl-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm yajl-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: json_verify CLI binary (JSON validator)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: JSON data files read from stdin via redirection
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses yajl version 2.1.0, matching the bc.dockerfile.

## About yajl

YAJL (Yet Another JSON Library) is a stream-oriented JSON parser library written in C.
The `json_verify` binary is a command-line tool that validates whether JSON input is well-formed.

The library heavily uses function pointers for JSON event callbacks:
- Null handler
- Boolean handler
- Integer/Double handler
- String handler
- Map start/end handlers
- Map key handler
- Array start/end handlers

This callback-based design makes yajl an excellent target for studying
function pointer behavior through fuzzing.
