# screen Fuzzing Resources

## External Resources

- dict: Created based on screen command-line options and commands from the manual
- in/: Self-created test cases covering various screen command-line patterns

## Usage

```bash
docker build -f screen/fuzz.dockerfile -t screen-fuzz .
docker run -it --rm screen-fuzz ./fuzz.sh
```

## Parallel Fuzzing

```bash
docker run -it --rm screen-fuzz ./fuzz.sh -j 4
```

## Monitor Progress

```bash
docker run -it --rm screen-fuzz ./whatsup.sh
```
