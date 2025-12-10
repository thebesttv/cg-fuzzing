# tcsh Fuzzing Resources

## External Resources

- dict: Created based on tcsh shell commands and syntax
- in/: Self-created test cases covering various tcsh script patterns

## Usage

```bash
docker build -f tcsh/fuzz.dockerfile -t tcsh-fuzz .
docker run -it --rm tcsh-fuzz ./fuzz.sh
```

## Parallel Fuzzing

```bash
docker run -it --rm tcsh-fuzz ./fuzz.sh -j 4
```

## Monitor Progress

```bash
docker run -it --rm tcsh-fuzz ./whatsup.sh
```
