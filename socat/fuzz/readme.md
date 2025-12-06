# socat Fuzzing Resources

## External Resources

- dict: Created based on socat address types and options from the manual
- in/: Self-created test cases covering various socat command-line patterns

## Usage

```bash
docker build -f socat/fuzz.dockerfile -t socat-fuzz .
docker run -it --rm socat-fuzz ./fuzz.sh
```

## Parallel Fuzzing

```bash
docker run -it --rm socat-fuzz ./fuzz.sh -j 4
```

## Monitor Progress

```bash
docker run -it --rm socat-fuzz ./whatsup.sh
```
