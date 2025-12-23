FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract utf8proc v2.11.2

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: utf8proc" > /work/proj && \
    echo "version: 2.11.2" >> /work/proj && \
    echo "source: https://github.com/JuliaStrings/utf8proc/archive/refs/tags/v2.11.2.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/JuliaStrings/utf8proc/archive/refs/tags/v2.11.2.tar.gz && \
    tar -xzf v2.11.2.tar.gz && \
    mv v2.11.2 build && \
    rm v2.11.2.tar.gz

WORKDIR /work/build

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
RUN mkdir -p /work/bc && \
    extract-bc utf8proc_fuzz && \
    mv utf8proc_fuzz.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
