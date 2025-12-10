# Htop Fuzzing Resources

## External Resources

- dict: Custom created for htop commands and configuration options
- in/: Self-created htoprc configuration files

## Usage

```bash
docker build -f htop/fuzz.dockerfile -t htop-fuzz .
docker run -it --rm htop-fuzz ./fuzz.sh
```

## Testing

To test htop with sample config:
```bash
docker run --rm htop-fuzz /out/htop --readonly -C /out/in/simple.conf
```
