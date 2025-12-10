# tig Fuzzing Resources

## External Resources

- dict: Created based on git/tig command keywords
- in/: Created with sample git log, diff, and status outputs

## Usage

```bash
docker build -f tig/fuzz.dockerfile -t tig-fuzz .
docker run -it --rm tig-fuzz ./fuzz.sh
```

## About tig

tig is a text-mode interface for git. It acts as a repository browser and can be used to visualize git history and diffs.
