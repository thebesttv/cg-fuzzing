# mg Fuzzing Resources

## External Resources

- dict: Created based on mg/emacs command syntax
- in/: Created with sample batch command files

## About mg

mg is a public domain Micro-Emacs style editor. It provides a lightweight
alternative to full Emacs while supporting many common editing commands.

## Fuzzing Target

This setup fuzzes the mg batch command parser. mg accepts a batch file 
via the `-b` flag which contains editor commands to execute. The fuzzer
tests mg's ability to handle malformed or unexpected batch command files.

## Usage

```bash
# Build the fuzz image
docker build -f mg/fuzz.dockerfile -t mg-fuzz .

# Run the fuzzer
docker run -it --rm mg-fuzz ./fuzz.sh

# Run with parallel fuzzers
docker run -it --rm mg-fuzz ./fuzz.sh -j 4
```

## Batch File Format

mg batch files contain one command per line. Commands are the same as
interactive mg commands, such as:
- `forward-char`
- `beginning-of-buffer`
- `find-file filename`
