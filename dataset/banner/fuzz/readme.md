# Banner Fuzzing Resources

## External Resources

- **dict**: Custom dictionary created based on banner command-line options and common text patterns
- **in/**: Small sample text inputs for banner

## Project Information

- **Project**: banner - Print large ASCII art banners
- **Version**: 1.3.2
- **Source**: https://shh.thathost.com/pub-unix/files/banner-1.3.2.tar.gz
- **Build System**: Makefile

## Usage

```bash
cd dataset
docker build -f banner/fuzz.dockerfile -t banner-fuzz .
docker run -it --rm banner-fuzz
```

Inside the container, you can use:
- `/work/bin-fuzz` - AFL++ fuzzing binary
- `/work/bin-cmplog` - AFL++ CMPLOG binary
- `/work/bin-cov` - LLVM coverage binary
- `/work/bin-uftrace` - uftrace profiling binary
- `/work/fuzz.sh` - Start fuzzing
- `/work/whatsup.sh` - Monitor fuzzing progress

## Fuzzing Target

Banner reads text from stdin or command line arguments and displays it as large ASCII art. The fuzzer tests various input texts, options, and edge cases to find potential vulnerabilities.
