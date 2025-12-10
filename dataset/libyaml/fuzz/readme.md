# libyaml Fuzzing Resources

This directory contains resources for fuzzing libyaml (run-parser) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (YAML syntax tokens)
- `in/` - Initial input corpus (YAML files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) is based on YAML specification and common patterns.
Reference: https://yaml.org/spec/1.2/spec.html

The initial input corpus contains basic YAML samples created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f libyaml/fuzz.dockerfile -t libyaml-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm libyaml-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm libyaml-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: run-parser CLI binary (YAML parser test tool)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: YAML data files passed as command line argument
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses libyaml version 0.2.5, matching the bc.dockerfile.

## About libyaml

LibYAML is a YAML parser and emitter library written in C.
The `run-parser` binary is a command-line tool that parses YAML files and outputs events.

The library heavily uses function pointers for YAML event callbacks:
- Stream start/end handlers
- Document start/end handlers
- Alias/anchor handlers
- Scalar handlers
- Sequence start/end handlers
- Mapping start/end handlers

This callback-based design makes libyaml an excellent target for studying
function pointer behavior through fuzzing.
