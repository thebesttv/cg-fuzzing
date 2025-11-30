# mxml (Mini-XML) Fuzzing Resources

This directory contains resources for fuzzing the Mini-XML library using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing
- `in/` - Initial input corpus (XML files)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file (`dict`) is custom-created based on XML syntax including:
- XML declarations and processing instructions
- Common tags and attributes
- CDATA and comments
- Entity references
- Namespace declarations

The initial input corpus contains sample XML files:
- minimal.xml - Minimal valid XML document
- simple.xml - Simple document with nested element
- attributes.xml - Elements with attributes
- cdata.xml - Document with CDATA and comments
- nested.xml - Deeply nested elements
- namespace.xml - Document with namespace

## Usage

Build the fuzzing Docker image:
```bash
docker build -f mxml/fuzz.dockerfile -t mxml-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm mxml-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm mxml-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: Custom fuzz_mxml harness using mxml's mxmlLoadFile API
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: XML files
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses Mini-XML version 4.0.4, matching the bc.dockerfile.

## Note on Harness

Since mxml is a library without a CLI tool, a custom harness (`fuzz_mxml.c`) was created
that reads XML from a file and parses it using mxml's API functions:
- mxmlOptionsNew() - Create parsing options
- mxmlLoadFile() - Load and parse XML from file
- mxmlWalkNext() - Walk through the parsed tree
- mxmlGetType(), mxmlGetText(), mxmlGetElement() - Access node information
