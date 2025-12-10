# fig2dev Fuzzing Resources

## About
fig2dev translates Fig format files to various graphics formats.

## Usage
```bash
docker build -f fig2dev/fuzz.dockerfile -t fig2dev-fuzz .
docker run -it --rm fig2dev-fuzz ./fuzz.sh
```
