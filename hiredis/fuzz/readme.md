# hiredis Fuzzing Resources

This directory contains resources for fuzzing hiredis using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (Redis RESP protocol tokens)
- `in/` - Initial input corpus (RESP protocol samples)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) is based on the Redis RESP2 and RESP3 protocol specifications:
- https://redis.io/docs/reference/protocol-spec/

The initial input corpus contains RESP protocol samples created for this project.

## Fuzzing Target

This fuzzing setup targets the hiredis RESP protocol reader using a custom harness (`fuzz_reader`).
The harness reads RESP protocol data from a file and passes it through the `redisReader` API to test
the protocol parsing functionality.

The harness:
1. Reads input data from a file (or stdin)
2. Creates a `redisReader` instance
3. Feeds the data using `redisReaderFeed()`
4. Retrieves and frees replies using `redisReaderGetReply()`

## Usage

Build the fuzzing Docker image:
```bash
docker build -f hiredis/fuzz.dockerfile -t hiredis-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm hiredis-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm hiredis-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: Custom harness for RESP protocol reader (`fuzz_reader`)
- **Same binary for bc.dockerfile**: Uses hiredis-test (links libhiredis statically)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Redis RESP protocol data
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses hiredis version 1.3.0, matching the bc.dockerfile.
