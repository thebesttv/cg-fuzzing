# bmake Fuzzing Resources

## External Resources

- dict: Created based on bmake/make makefile syntax and directives
- in/: Self-created test cases with simple Makefiles

## Usage

```bash
docker build -f bmake/fuzz.dockerfile -t bmake-fuzz .
docker run -it --rm bmake-fuzz ./fuzz.sh
```

## Parallel Fuzzing

```bash
docker run -it --rm bmake-fuzz ./fuzz.sh -j 4
```

## Monitor Progress

```bash
docker run -it --rm bmake-fuzz ./whatsup.sh
```
