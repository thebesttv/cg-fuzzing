# remind Fuzzing Resources

## About remind

Remind is a sophisticated calendar and alarm program for UNIX/Linux. It reads reminder files with a custom scripting language to define events, appointments, and recurring reminders.

## External Resources

- dict: Created for this project based on Remind file format syntax
- in/: Created for this project with sample remind files

## Usage

Build the fuzzing Docker image:
```bash
docker build -f remind/fuzz.dockerfile -t remind-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm remind-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm remind-fuzz ./fuzz.sh -j 4
```

## Fuzzing Strategy

- **Target**: remind CLI binary (reads .rem files)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage of comparison operations
- **Input**: Remind reminder files (.rem format)
- **Static linking**: For better performance and reproducibility

## Version

This fuzzing setup uses Remind version 06.02.01.
