# html2text Fuzzing Resources

## External Resources

- dict: Created based on common HTML tags and attributes
- in/: Created with sample HTML files containing various HTML structures

## Usage

```bash
docker build -f html2text/fuzz.dockerfile -t html2text-fuzz .
docker run -it --rm html2text-fuzz ./fuzz.sh
```

## About html2text

html2text is an advanced HTML-to-text converter that converts HTML documents to plain text format.
