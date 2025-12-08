# enchive Fuzzing Resources

## External Resources

- dict: Custom enchive dictionary with command options and crypto-related strings
- in/: Sample plain text and binary files for fuzzing

## Usage

```bash
docker build -f enchive/fuzz.dockerfile -t enchive-fuzz .
docker run -it --rm enchive-fuzz ./fuzz.sh
```

## Monitoring

```bash
docker run -it --rm enchive-fuzz ./whatsup.sh
```

## Target

Fuzzes `enchive fingerprint` which reads and processes file input without needing keys.
