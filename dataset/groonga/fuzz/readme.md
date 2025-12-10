# groonga Fuzzing Resources

## External Resources

- dict: Created based on groonga query language syntax and commands
- in/: Self-created sample queries and JSON data

## Usage

```bash
docker build -f groonga/fuzz.dockerfile -t groonga-fuzz .
docker run -it --rm groonga-fuzz ./fuzz.sh
```

## Fuzzing Target

The fuzzing target is `groonga` CLI tool with `--file` option, which processes command files for full-text search operations.
