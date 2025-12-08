# vim Fuzzing Resources

## External Resources

- dict: Custom created Vim command dictionary
- in/: Custom created input samples (text files and Vimscript files)

## Usage

```bash
docker build -f vim/fuzz.dockerfile -t vim-fuzz .
docker run -it --rm vim-fuzz ./fuzz.sh
```

## Fuzzing vim

vim is a powerful text editor with extensive scripting capabilities. The fuzzing targets:
- Vimscript parsing and execution
- Text file editing operations
- Command-line commands
- Buffer manipulation

The fuzzer uses vim in batch mode with `-u NONE -i NONE -e -s -c "qa!" -S @@` to:
- `-u NONE`: Skip vimrc files
- `-i NONE`: Skip viminfo files
- `-e -s`: Silent mode (Ex mode, batch)
- `-c "qa!"`: Quit all without saving
- `-S @@`: Source the fuzzed file
