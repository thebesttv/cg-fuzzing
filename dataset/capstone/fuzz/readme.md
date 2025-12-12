# capstone Fuzzing Resources

This directory contains resources for fuzzing Capstone disassembly framework using AFL++.

## Files

- `dict` - Dictionary file for AFL++ fuzzing (architecture names, opcodes)
- `in/` - Initial input corpus (43 seeds covering 20+ architectures)
- `fuzz.sh` - Script to start fuzzing
- `whatsup.sh` - Script to monitor fuzzing progress
- `fuzz_harness.c` - Custom fuzzing harness based on Capstone's official fuzzer
- `platform.c` / `platform.h` - Platform definitions from Capstone

## External Resources

- `fuzz_harness.c`: Based on Capstone's official `fuzz_disasm.c` from suite/fuzz/
- `platform.c` / `platform.h`: From Capstone repository
- Seeds: Generated to cover diverse architectures (X86, ARM, MIPS, RISC-V, PPC, SPARC, etc.)

## Fuzzing Strategy

### Why the New Approach?

The previous setup only fuzzed `cstool` with x64 architecture, achieving only 0.17% coverage. The official Capstone fuzzing approach uses a custom harness that:

1. **Uses the first byte to select architecture**: Each input's first byte determines which of 60+ architecture/mode combinations to test
2. **Directly exercises the disassembly engine**: Calls `cs_disasm()` and accesses detailed instruction information
3. **Covers many code paths**: Tests X86-32/64, ARM, AARCH64, MIPS, PPC, SPARC, RISC-V, SystemZ, M68K, EVM, WASM, BPF, and more

### Input Format

Each input file has the following structure:
- **Byte 0**: Platform selector (0-59), determines arch+mode
- **Bytes 1+**: Machine code to disassemble

The platform selector maps to different architectures via modulo operation:
- 0 = X86-32, 1 = X86-64, 2 = ARM, 3 = Thumb, 7 = AArch64
- 8-13 = Various MIPS modes, 14 = PPC64, 15-16 = SPARC
- 17 = SystemZ, 23 = M68K, 25 = EVM, 28 = WASM, 29-32 = BPF
- 44-45 = RISC-V, and more...

### Seed Corpus

The `in/` directory contains 43 seed files covering:
- X86-32 and X86-64 (nops, returns, prologues, syscalls)
- ARM, Thumb, ARM-V8, AArch64
- MIPS32/64 (both endianness)
- PowerPC 64-bit
- SPARC
- SystemZ
- RISC-V 32/64
- M68K
- EVM (Ethereum VM)
- WebAssembly
- BPF/eBPF

This diverse corpus ensures AFL++ explores all major code paths in Capstone.

## Usage

Build the fuzzing Docker image:
```bash
cd dataset
docker build -f capstone/fuzz.dockerfile -t capstone-fuzz .
```

Run the fuzzer:
```bash
docker run -it --rm capstone-fuzz ./fuzz.sh
```

For parallel fuzzing with multiple cores:
```bash
docker run -it --rm capstone-fuzz ./fuzz.sh -j 4
```

Monitor progress:
```bash
docker run -it --rm capstone-fuzz ./whatsup.sh
```

## Expected Improvements

With this new approach, we expect:
- **Much higher code coverage**: From 0.17% to potentially 10%+ (60x improvement)
- **Better bug finding**: Exercising all architectures increases bug surface
- **Faster exploration**: Seeds cover diverse paths, helping AFL++ mutate effectively

## Version

This fuzzing setup uses Capstone version 5.0.3, matching the bc.dockerfile.

