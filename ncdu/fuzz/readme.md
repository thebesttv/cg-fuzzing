# Ncdu Fuzzing Resources

## External Resources

- dict: Custom created for ncdu commands and export format
- in/: Self-created JSON files in ncdu export format

## Usage

```bash
docker build -f ncdu/fuzz.dockerfile -t ncdu-fuzz .
docker run -it --rm ncdu-fuzz ./fuzz.sh
```

## Testing

To test ncdu with sample input:
```bash
docker run --rm ncdu-fuzz /out/ncdu -f /out/in/simple.json
```
