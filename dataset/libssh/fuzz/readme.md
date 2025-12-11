# libssh Fuzzing Resources

Fuzzing resources for libssh (SSH protocol library) using AFL++.

## Usage

```bash
docker build -f libssh/fuzz.dockerfile -t libssh-fuzz .
docker run -it --rm libssh-fuzz ./fuzz.sh
```

## Version

libssh 0.10.6
