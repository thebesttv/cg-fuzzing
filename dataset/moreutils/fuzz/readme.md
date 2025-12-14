# moreutils Fuzzing Resources

Fuzzing resources for moreutils Unix utilities.

## Files

- `dict` - Dictionary file for AFL++ fuzzing
- `in/` - Initial input corpus
- `fuzz.sh` - Script to start fuzzing (targets `pee`)
- `whatsup.sh` - Script to monitor fuzzing progress

## Usage

```bash
cd dataset
docker build -f moreutils/fuzz.dockerfile -t moreutils-fuzz .
docker run -it --rm moreutils-fuzz ./fuzz.sh
```

## Version

moreutils version 0.69, matching the bc.dockerfile.
