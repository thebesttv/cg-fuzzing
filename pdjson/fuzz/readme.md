# pdjson Fuzzing Resources

pdjson is a public domain JSON parser focused on simplicity.

## Target Binary
- `pretty` - JSON pretty printer

## Usage
```bash
docker build -f pdjson/fuzz.dockerfile -t pdjson-fuzz .
docker run -it --rm pdjson-fuzz ./fuzz.sh
```
