# libexpat Fuzzing Resources

This directory contains resources for fuzzing libexpat (xmlwf) using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (XML syntax tokens)
- `in/` - Initial input corpus (XML files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) is based on the xml.dict from Google OSS-Fuzz project:
- Source: https://github.com/google/oss-fuzz/blob/master/projects/expat/xml.dict
- Extended with additional XML tokens

The initial input corpus contains basic XML samples created for this project.

## Usage

Build the fuzzing Docker image:
```bash
docker build -f libexpat/fuzz.dockerfile -t libexpat-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm libexpat-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm libexpat-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: xmlwf CLI binary (XML well-formedness checker)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: XML data files processed by xmlwf
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses libexpat version 2.7.3, matching the bc.dockerfile.

## About libexpat

libexpat is a stream-oriented XML parser library written in C. The `xmlwf` binary
is a command-line tool that checks whether XML documents are well-formed.

The library heavily uses function pointers for XML event callbacks:
- Element handlers (start/end)
- Character data handlers
- Processing instruction handlers
- Comment handlers
- CDATA section handlers
- External entity reference handlers
- etc.

This callback-based design makes libexpat an excellent target for studying
function pointer behavior through fuzzing.
