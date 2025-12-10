# jq-harness Fuzzing Resources

This directory contains resources for fuzzing jq using the `jq_fuzz_compile` harness with AFL++.

## Harness

Unlike the `jq` project which fuzzes the CLI binary, this project uses the `jq_fuzz_compile` harness from the jq source tree. This harness tests the jq filter compilation functionality:

1. `jq_init` - Initialize jq state
2. `jq_compile` - Compile a jq filter program
3. `jq_dump_disassembly` - Dump compiled bytecode

The harness takes raw input bytes as a jq filter expression and tests the compilation process.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (same as jq project)
- `in/` - Initial input corpus (jq filter expressions)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) is based on the jq.dict from Google OSS-Fuzz project:
- Source: https://github.com/google/oss-fuzz/blob/master/projects/jq/jq.dict
- Extended with additional jq keywords and operators

The harness `jq_fuzz_compile.c` is from the jq source tree:
- Source: https://github.com/jqlang/jq/blob/master/tests/jq_fuzz_compile.c

## Usage

Build the fuzzing Docker image:
```bash
docker build -f jq-harness/fuzz.dockerfile -t jq-harness-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm jq-harness-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm jq-harness-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: jq_fuzz_compile harness (library-level fuzzing)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: jq filter expressions
- **Static linking**: For better performance and reproducibility

## Bitcode Extraction

Build the bitcode Docker image:
```bash
docker build -f jq-harness/bc.dockerfile -t jq-harness-bc .
```

Copy bitcode files:
```bash
container_id=$(docker create jq-harness-bc)
docker cp "$container_id:/home/SVF-tools/bc/." jq-harness/bc/
docker rm "$container_id"
```

## Version

This fuzzing setup uses jq version 1.8.1, matching the jq project.
