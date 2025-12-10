# bzip2 Fuzzing Resources

This directory contains resources for fuzzing bzip2 using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (bzip2 format tokens)
- `in/` - Initial input corpus (bzip2 compressed files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) is based on the bzip2 file format specification.
Reference: https://en.wikipedia.org/wiki/Bzip2#File_format

The initial input corpus contains basic bzip2 compressed samples.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f bzip2/fuzz.dockerfile -t bzip2-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm bzip2-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm bzip2-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: bzip2 CLI binary (decompression mode)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: bzip2 compressed files decompressed with `-d -k -f` flags
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses bzip2 version 1.0.8, matching the bc.dockerfile.

## About bzip2

bzip2 is a free and open-source file compression program that uses the
Burrows–Wheeler algorithm. It compresses files using Huffman coding.

The decompression path is particularly interesting for fuzzing as it needs to:
- Parse and validate bzip2 headers
- Handle Huffman decoding
- Process run-length encoding
- Verify CRC checksums

This makes bzip2 an excellent target for fuzzing to find parsing vulnerabilities.
