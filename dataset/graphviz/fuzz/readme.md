# graphviz Fuzzing Resources

## External Resources

- dict: Custom created DOT language dictionary
- in/: Custom created DOT graph samples

## Usage

```bash
docker build -f graphviz/fuzz.dockerfile -t graphviz-fuzz .
docker run -it --rm graphviz-fuzz ./fuzz.sh
```

## Fuzzing graphviz

graphviz is a graph visualization software. The fuzzing targets the `dot` tool which:
- Parses DOT language graph descriptions
- Renders graphs to various output formats
- Handles complex layout algorithms

The fuzzer uses `-Tpng -o /dev/null @@` to:
- `-Tpng`: Render to PNG format (exercises full rendering pipeline)
- `-o /dev/null`: Discard output (we only care about crashes)
- `@@`: Input file placeholder for AFL++
