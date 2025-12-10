# calc Fuzzing Resources

## Resources
- dict: Mathematical operators and functions
- in/: Sample calculations

## Usage
```bash
docker build -f calc/fuzz.dockerfile -t calc-fuzz .
docker run -it --rm calc-fuzz ./fuzz.sh
```
