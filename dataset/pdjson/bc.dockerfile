FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download pdjson (streaming JSON parser)
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/skeeto/pdjson/archive/refs/heads/master.tar.gz -O pdjson.tar.gz && \
    tar -xzf pdjson.tar.gz && \
    rm pdjson.tar.gz

WORKDIR /home/SVF-tools/pdjson-master

# Build with static linking and WLLVM
# Build the pretty tool which reads and reformats JSON
RUN wllvm -c -g -O0 -Xclang -disable-llvm-passes -std=c99 pdjson.c -o pdjson.o && \
    wllvm -c -g -O0 -Xclang -disable-llvm-passes -std=c99 tests/pretty.c -o tests/pretty.o && \
    wllvm -g -O0 -Xclang -disable-llvm-passes -static -Wl,--allow-multiple-definition -o pretty tests/pretty.o pdjson.o

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc pretty && \
    mv pretty.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
