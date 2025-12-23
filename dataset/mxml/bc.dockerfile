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

# Download and extract mxml 4.0.4

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: mxml" > /work/proj && \
    echo "version: 4.0.4" >> /work/proj && \
    echo "source: https://github.com/michaelrsweet/mxml/releases/download/v4.0.4/mxml-4.0.4.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/michaelrsweet/mxml/releases/download/v4.0.4/mxml-4.0.4.tar.gz && \
    tar -xzf mxml-4.0.4.tar.gz && \
    mv mxml-4.0.4 build && \
    rm mxml-4.0.4.tar.gz

WORKDIR /work/build

# Copy the fuzzing harness
COPY mxml/fuzz_mxml.c .

# Configure and build mxml with WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

RUN make -j$(nproc)

# Compile the fuzzing harness with the library
RUN wllvm -g -O0 -Xclang -disable-llvm-passes -I. -static -Wl,--allow-multiple-definition \
    -o fuzz_mxml fuzz_mxml.c libmxml4.a -lm -lpthread

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc fuzz_mxml && \
    mv fuzz_mxml.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
