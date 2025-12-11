# libconfuse Fuzzing Resources

## Resources

- dict: Configuration file format keywords
- in/: Config file samples (simple, empty, key-value)

## Target Binary

Fuzzing `simple` example program which parses configuration files.

## Usage

```bash
docker build -f libconfuse/fuzz.dockerfile -t libconfuse-fuzz .
docker run -it --rm libconfuse-fuzz ./fuzz.sh
```
