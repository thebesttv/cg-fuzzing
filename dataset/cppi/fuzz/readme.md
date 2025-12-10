# cppi Fuzzing Resources

## External Resources

- dict: Created based on C preprocessor directives and keywords
- in/: Created with sample C files containing various preprocessor patterns

## Usage

```bash
docker build -f cppi/fuzz.dockerfile -t cppi-fuzz .
docker run -it --rm cppi-fuzz ./fuzz.sh
```

## About cppi

cppi indents C preprocessor directives to reflect their nesting and ensures proper formatting.
