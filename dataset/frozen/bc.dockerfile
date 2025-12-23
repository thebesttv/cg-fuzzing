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

# Download and extract frozen 1.7

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: frozen" > /work/proj && \
    echo "version: 1.7" >> /work/proj && \
    echo "source: https://github.com/cesanta/frozen/archive/refs/tags/1.7.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/cesanta/frozen/archive/refs/tags/1.7.tar.gz && \
    tar -xzf 1.7.tar.gz && \
    mv 1.7 build && \
    rm 1.7.tar.gz

WORKDIR /work/build

# Copy the fuzzing harness
COPY frozen/fuzz_json.c .

# Compile the fuzzing harness with WLLVM
RUN wllvm -g -O0 -Xclang -disable-llvm-passes -static -Wl,--allow-multiple-definition -o fuzz_json fuzz_json.c frozen.c -lm

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc fuzz_json && \
    mv fuzz_json.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
