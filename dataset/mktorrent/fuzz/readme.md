# mktorrent Fuzzing Resources

This directory contains resources for fuzzing mktorrent (BitTorrent metainfo file creator) using AFL++.

## Files

- `dict` - Dictionary file containing BitTorrent dictionary keys
- `in/` - Initial input corpus with test directories
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress

## External Resources

The dictionary file was created specifically for this project, containing:
- Common BitTorrent metainfo dictionary keys
- Typical tracker URLs
- Common piece lengths

## Usage

Build the fuzzing Docker image from the dataset directory:
```bash
cd dataset
docker build -f mktorrent/fuzz.dockerfile -t mktorrent-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm mktorrent-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm mktorrent-fuzz ./fuzz.sh -j 4
```

Monitor fuzzing progress (in another terminal):
```bash
docker exec -it <container_id> ./whatsup.sh
```

Or use watch mode:
```bash
docker exec -it <container_id> ./whatsup.sh -w
```

## Fuzzing Strategy

- **Target**: mktorrent CLI binary (creates .torrent files)
- **Instrumentation**: afl-clang-lto (prevents hash collisions)
- **CMPLOG**: Enabled for better coverage
- **Input**: Directory paths (mktorrent reads from filesystem)
- **Static linking**: For better performance and reproducibility
- **Command**: `mktorrent -o /tmp/test.torrent <input_path>`

## Version

This fuzzing setup uses mktorrent version 1.1, matching the bc.dockerfile.
