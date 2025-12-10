# daemonize Fuzzing Resources

## External Resources

- dict: Created based on command line options
- in/: Simple test inputs

## Usage

```bash
docker build -f daemonize/fuzz.dockerfile -t daemonize-fuzz .
docker run -it --rm daemonize-fuzz ./fuzz.sh
```

## About daemonize

daemonize is a tool to run a command as a Unix daemon.
