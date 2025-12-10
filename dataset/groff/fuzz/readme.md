# groff Fuzzing Resources

## Usage
```bash
docker build -f groff/fuzz.dockerfile -t groff-fuzz .
docker run -it --rm groff-fuzz ./fuzz.sh
```
