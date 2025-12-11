# upx Fuzzing Resources

## External Resources

- dict: Created based on upx command-line options and executable format signatures
- in/: Self-created test cases with small executable files (ELF format)

## Usage

```bash
docker build -f upx/fuzz.dockerfile -t upx-fuzz .
docker run -it --rm upx-fuzz ./fuzz.sh
```

## Parallel Fuzzing

```bash
docker run -it --rm upx-fuzz ./fuzz.sh -j 4
```

## Monitor Progress

```bash
docker run -it --rm upx-fuzz ./whatsup.sh
```
