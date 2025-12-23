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

# Download and extract mpack 1.1.1 (amalgamation version)

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: mpack" > /work/proj && \
    echo "version: 1.1.1" >> /work/proj && \
    echo "source: https://github.com/ludocode/mpack/releases/download/v1.1.1/mpack-amalgamation-1.1.1.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/ludocode/mpack/releases/download/v1.1.1/mpack-amalgamation-1.1.1.tar.gz && \
    tar -xzf mpack-amalgamation-1.1.1.tar.gz && \
    mv mpack-amalgamation-1.1.1 build && \
    rm mpack-amalgamation-1.1.1.tar.gz

WORKDIR /work/build

# Copy the fuzzing harness
COPY mpack/fuzz_mpack.c .

# Compile the fuzzing harness with WLLVM and mpack library
# mpack is a single-file library, we can compile it directly
RUN wllvm -g -O0 -Xclang -disable-llvm-passes -DMPACK_READER=1 -DMPACK_EXTENSIONS=1 \
    -static -Wl,--allow-multiple-definition \
    -o fuzz_mpack fuzz_mpack.c src/mpack/mpack.c -lm

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc fuzz_mpack && \
    mv fuzz_mpack.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
