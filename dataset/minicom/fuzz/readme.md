# minicom Fuzzing Resources

## Resources
- dict: Custom minicom/AT commands
- in/: AT command samples

## Usage
```bash
docker build -f minicom/fuzz.dockerfile -t minicom-fuzz .
docker run -it --rm minicom-fuzz ./fuzz.sh
```
