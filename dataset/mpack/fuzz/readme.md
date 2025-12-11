# mpack (MessagePack) Fuzzing Resources

This directory contains resources for fuzzing the MPack library (MessagePack for C) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing
- `in/` - Initial input corpus (MessagePack files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) is custom-created based on MessagePack binary format including:
- Format family type bytes (nil, bool, int, float, str, bin, array, map, ext)
- Size prefixes for various data types
- Common type markers

The initial input corpus contains sample MessagePack files:
- nil.msgpack - nil value
- true.msgpack, false.msgpack - Boolean values
- int42.msgpack, int_neg1.msgpack - Integer values
- str_hello.msgpack - String "hello"
- empty_array.msgpack, array_123.msgpack - Array values
- empty_map.msgpack, map_a1.msgpack - Map values
- float32.msgpack, float64.msgpack - Floating point values

## Usage

Build the fuzzing Docker image:
```bash
docker build -f mpack/fuzz.dockerfile -t mpack-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm mpack-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm mpack-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: Custom fuzz_mpack harness using mpack's reader API
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: MessagePack binary files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses MPack version 1.1.1 (amalgamation), matching the bc.dockerfile.

## Note on Harness

Since mpack is a library without a CLI tool, a custom harness (`fuzz_mpack.c`) was created
that reads MessagePack data from a file and parses it using mpack's reader API:
- mpack_reader_init_data() - Initialize reader with data buffer
- mpack_read_tag() - Read the next MessagePack value
- mpack_skip_bytes() - Skip binary data
- Recursive parsing for arrays and maps with depth limiting

## About MessagePack

MessagePack is an efficient binary serialization format. It lets you exchange data among
multiple languages like JSON, but it's faster and smaller. This makes it an interesting
target for fuzzing as parsers need to handle various binary format edge cases.
