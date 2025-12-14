# lrzip Fuzzing Resources

## External Resources

- dict: ZIP dictionary from AFL++ (https://github.com/AFLplusplus/AFLplusplus/blob/stable/dictionaries/zip.dict)
- in/: Self-created compressed file samples (gzip and bzip2)

## Usage

```bash
cd dataset
docker build -f lrzip/fuzz.dockerfile -t lrzip-fuzz .
docker run -it --rm lrzip-fuzz
```

In the container, you can use:
- `/work/bin-fuzz` - AFL++ fuzzing binary
- `/work/bin-cmplog` - AFL++ CMPLOG binary
- `/work/bin-cov` - LLVM coverage binary
- `/work/bin-uftrace` - uftrace profiling binary
- `/work/fuzz.sh` - Start fuzzing
- `/work/whatsup.sh` - Monitor fuzzing progress

## About lrzip

lrzip is a compression program optimized for large files. It uses long-range redundancy reduction (rzip) combined with various compression backends (lzma, gzip, bzip2, lzo, zpaq, lz4). The fuzzer tests lrzip's decompression capabilities with the `-d` flag.
