# libunistring Fuzzing Resources

Fuzzing resources for libunistring (Unicode string library) using AFL++.

## Usage

```bash
docker build -f libunistring/fuzz.dockerfile -t libunistring-fuzz .
docker run -it --rm libunistring-fuzz ./fuzz.sh
```

## Version

libunistring 1.2
