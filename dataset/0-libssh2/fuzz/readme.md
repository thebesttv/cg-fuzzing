# libssh2 Fuzzing Resources

## Resources
- dict: SSH protocol keywords
- in/: SSH protocol samples

## Target Binary
Fuzzing SSH2 example program.

## Usage
```bash
docker build -f libssh2/fuzz.dockerfile -t libssh2-fuzz .
docker run -it --rm libssh2-fuzz ./fuzz.sh
```
