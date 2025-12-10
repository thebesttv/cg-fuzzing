# util-linux (libuuid) Fuzzing Resources

## Resources
- dict: UUID command-line options
- in/: Sample inputs

## Target Binary
Fuzzing `uuidgen` utility.

## Usage
```bash
docker build -f util-linux/fuzz.dockerfile -t util-linux-fuzz .
docker run -it --rm util-linux-fuzz ./fuzz.sh
```
