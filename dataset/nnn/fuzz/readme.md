# nnn Fuzzing Resources

## Note

nnn is an interactive terminal file manager and is NOT well-suited for traditional AFL++ file-based fuzzing. This fuzzing setup is provided for completeness but has limited effectiveness.

## External Resources

- dict: Self-created minimal command keywords
- in/: Self-created minimal inputs

## Usage

```bash
docker build -f nnn/fuzz.dockerfile -t nnn-fuzz .
docker run -it --rm nnn-fuzz ./fuzz.sh
```

## Limitations

As an interactive program, nnn expects terminal input and user interaction. AFL++ fuzzing via file input is not effective for this type of program.
