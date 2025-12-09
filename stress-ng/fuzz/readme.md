# stress-ng Fuzzing Resources

## External Resources

- dict: Created based on stress-ng command line options
- in/: Created with basic command line inputs

## Usage

```bash
docker build -f stress-ng/fuzz.dockerfile -t stress-ng-fuzz .
docker run -it --rm stress-ng-fuzz ./fuzz.sh
```

## About stress-ng

stress-ng is a tool that stress tests a computer system in various selectable ways. It exercises various physical subsystems of a computer as well as various operating system kernel interfaces. It has over 280 different stress tests (called stressors) that can be used to stress the system.
