# httrack Fuzzing Resources

## External Resources

- dict: Created based on httrack command line options
- in/: Created with basic command line inputs

## Usage

```bash
docker build -f httrack/fuzz.dockerfile -t httrack-fuzz .
docker run -it --rm httrack-fuzz ./fuzz.sh
```

## About httrack

HTTrack is a free and easy-to-use offline browser utility. It allows you to download a World Wide Web site from the Internet to a local directory, building recursively all directories, getting HTML, images, and other files from the server to your computer. HTTrack arranges the original site's relative link-structure.
