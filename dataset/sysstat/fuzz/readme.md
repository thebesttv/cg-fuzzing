# sysstat Fuzzing Resources

## External Resources

- dict: Created based on sar command line options
- in/: Created with basic command line inputs

## Usage

```bash
docker build -f sysstat/fuzz.dockerfile -t sysstat-fuzz .
docker run -it --rm sysstat-fuzz ./fuzz.sh
```

## About sysstat

The sysstat package contains various utilities, common to many commercial Unixes, to monitor system performance and usage activity. It includes sar (System Activity Reporter), sadc (System Activity Data Collector), iostat, mpstat, pidstat, and more.
