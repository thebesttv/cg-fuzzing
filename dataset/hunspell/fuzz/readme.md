# hunspell Fuzzing Resources

## External Resources

- dict: Custom hunspell affix format dictionary
- in/: Self-created minimal dictionary and affix files (.dic and .aff pairs)

## Usage

```bash
docker build -f hunspell/fuzz.dockerfile -t hunspell-fuzz .
docker run -it --rm hunspell-fuzz ./fuzz.sh
```

## About hunspell

Hunspell is a free spell checker and morphological analyzer library used by many applications including LibreOffice, Firefox, and Chrome. It supports complex morphology and character encodings.
