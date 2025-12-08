# wget Fuzzing Resources

## External Resources

- dict: Extracted from wget source tree (fuzz/*.dict)
- in/: Custom created input samples (URLs and config files)

## Usage

```bash
docker build -f wget/fuzz.dockerfile -t wget-fuzz .
docker run -it --rm wget-fuzz ./fuzz.sh
```

## Fuzzing wget

wget is a network downloader supporting HTTP, HTTPS, and FTP protocols. The fuzzing targets:
- URL parsing
- Config file parsing (--input-file)
- HTTP header processing
- FTP protocol handling

The fuzzer uses `--input-file=@@` to feed input files to wget for parsing.
