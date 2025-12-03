# Nano Fuzzing Resources

## External Resources

- dict: Custom created for nano control sequences and commands
- in/: Self-created text files covering different input types

## Usage

```bash
docker build -f nano/fuzz.dockerfile -t nano-fuzz .
docker run -it --rm nano-fuzz ./fuzz.sh
```

## Testing

To test nano with sample input:
```bash
docker run --rm nano-fuzz /out/nano /out/in/simple.txt
```
