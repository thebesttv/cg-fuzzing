# Tcl Fuzzing Resources

## External Resources

- dict: Custom Tcl command and syntax dictionary
- in/: Self-created minimal Tcl scripts covering basic language features

## Usage

```bash
docker build -f tcl/fuzz.dockerfile -t tcl-fuzz .
docker run -it --rm tcl-fuzz ./fuzz.sh
```

## About Tcl

Tcl (Tool Command Language) is a powerful scripting language with simple syntax. tclsh is the Tcl shell interpreter that executes Tcl scripts.
