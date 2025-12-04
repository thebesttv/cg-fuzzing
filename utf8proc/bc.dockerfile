FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract utf8proc v2.11.2
WORKDIR /home/SVF-tools
RUN wget https://github.com/JuliaStrings/utf8proc/archive/refs/tags/v2.11.2.tar.gz && \
    tar -xzf v2.11.2.tar.gz && \
    rm v2.11.2.tar.gz

WORKDIR /home/SVF-tools/utf8proc-2.11.2

# Build utf8proc library as static with WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    make libutf8proc.a

# Build the fuzzer binary (uses fuzz_main.c + fuzzer.c for standalone AFL fuzzing)
RUN wllvm \
    -g -O0 -Xclang -disable-llvm-passes \
    -I. \
    -static -Wl,--allow-multiple-definition \
    -o utf8proc_fuzz \
    test/fuzz_main.c test/fuzzer.c libutf8proc.a

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc utf8proc_fuzz && \
    mv utf8proc_fuzz.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
