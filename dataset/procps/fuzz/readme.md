# procps Fuzzing Resources

## External Resources

- dict: Created based on ps command line options
- in/: Created with basic command line inputs

## Usage

```bash
docker build -f procps/fuzz.dockerfile -t procps-fuzz .
docker run -it --rm procps-fuzz ./fuzz.sh
```

## About procps

procps is a set of command line and full screen utilities that provide information out of the pseudo-filesystem most commonly located at /proc. This filesystem provides a simple interface to the kernel data structures. The programs of procps generally concentrate on the structures that describe the processes running on the system.
