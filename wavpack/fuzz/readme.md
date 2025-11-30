# WavPack Fuzzing Resources

## External Resources

- dict: Created based on WavPack file format structure
- in/: Contains minimal WavPack file seed

## About WavPack

WavPack is a completely open audio compression format providing lossless, 
high-quality lossy, and a unique hybrid compression mode. The CLI tools include:
- wavpack: Compress audio files to .wv format
- wvunpack: Decompress .wv files (fuzzing target)
- wvgain: Apply ReplayGain to WavPack files
- wvtag: Add/edit/display tags on WavPack files

## Fuzzing Target

This setup fuzzes `wvunpack`, the WavPack decoder. This is a good target because:
1. It parses complex binary file formats
2. It has historically had vulnerabilities in parsing
3. It's commonly used in audio applications

## Recommended Seeds

For better fuzzing coverage, add real WavPack files to the `in/` directory:
```bash
# Create a simple wav file and convert it
sox -n -r 44100 -c 2 test.wav synth 0.1 sine 440
wavpack test.wav -o test.wv
cp test.wv in/
```

## Usage

```bash
# Build the fuzz image
docker build -f wavpack/fuzz.dockerfile -t wavpack-fuzz .

# Run the fuzzer
docker run -it --rm wavpack-fuzz ./fuzz.sh

# Run with parallel fuzzers
docker run -it --rm wavpack-fuzz ./fuzz.sh -j 4
```
