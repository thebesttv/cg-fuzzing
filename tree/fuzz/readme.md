# Tree Fuzzing Resources

## External Resources

- dict: Custom created for tree command options
- in/: Self-created argument patterns

## Usage

```bash
docker build -f tree/fuzz.dockerfile -t tree-fuzz .
docker run -it --rm tree-fuzz ./fuzz.sh
```

## Testing

To test tree with sample arguments:
```bash
docker run --rm tree-fuzz /out/tree --version
docker run --rm tree-fuzz /out/tree -a /tmp
```
