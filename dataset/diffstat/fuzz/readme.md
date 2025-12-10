# diffstat Fuzzing Resources

## Usage
```bash
docker build -f diffstat/fuzz.dockerfile -t diffstat-fuzz .
docker run -it --rm diffstat-fuzz ./fuzz.sh
```
