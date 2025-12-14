# minisign Fuzzing Resources

Fuzzing resources for minisign signature verification tool.

## Files

- `dict` - Dictionary file for AFL++ fuzzing
- `in/` - Initial input corpus
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## Usage

```bash
cd dataset
docker build -f minisign/fuzz.dockerfile -t minisign-fuzz .
docker run -it --rm minisign-fuzz ./fuzz.sh
```

## Version

minisign version 0.11, matching the bc.dockerfile.
