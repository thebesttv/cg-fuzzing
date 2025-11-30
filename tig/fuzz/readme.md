# tig Fuzzing Resources

## External Resources

- dict: Created based on tig configuration file syntax (tigrc format)
- in/: Created based on tig configuration file examples

## About tig

tig is a text-mode interface for Git. It provides a visual interface for navigating 
git history, viewing diffs, and other operations.

## Fuzzing Target

This setup fuzzes the tigrc configuration file parser. tig accepts a custom 
configuration file via the `-C` flag. The fuzzer tests tig's ability to handle
malformed or unexpected configuration files.

## Usage

```bash
# Build the fuzz image
docker build -f tig/fuzz.dockerfile -t tig-fuzz .

# Run the fuzzer
docker run -it --rm tig-fuzz ./fuzz.sh

# Run with parallel fuzzers
docker run -it --rm tig-fuzz ./fuzz.sh -j 4
```

## Configuration File Format

tigrc files support:
- `set` commands for options
- `bind` commands for key bindings
- `color` commands for color schemes
- `source` for including other files
- Comments starting with `#`
