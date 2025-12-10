# libxslt Fuzzing Resources

## External Resources

- dict: Custom XSLT/XML dictionary based on XSLT 1.0 specification
- in/: Self-created minimal XSLT stylesheets covering basic transformations

## Usage

```bash
docker build -f libxslt/fuzz.dockerfile -t libxslt-fuzz .
docker run -it --rm libxslt-fuzz ./fuzz.sh
```

## About libxslt

libxslt is the XSLT C library developed for the GNOME project. xsltproc is a command-line tool for applying XSLT stylesheets to XML documents.
