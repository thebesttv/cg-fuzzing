# msgpack-c Fuzzing Resources

## External Resources

- dict: Based on MessagePack format specification
- in/: Created initial seed inputs (empty, map, array, fixint)

## Target Binary

Fuzzing `lib_buffer_unpack` example program which exercises MessagePack buffer unpacking.

## Usage

```bash
docker build -f msgpack-c/fuzz.dockerfile -t msgpack-c-fuzz .
docker run -it --rm msgpack-c-fuzz ./fuzz.sh
```

For parallel fuzzing:
```bash
docker run -it --rm msgpack-c-fuzz ./fuzz.sh -j 4
```

Monitor progress:
```bash
docker run -it --rm msgpack-c-fuzz ./whatsup.sh
```
