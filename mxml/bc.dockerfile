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

# Download and extract mxml 4.0.4
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/michaelrsweet/mxml/releases/download/v4.0.4/mxml-4.0.4.tar.gz && \
    tar -xzf mxml-4.0.4.tar.gz && \
    rm mxml-4.0.4.tar.gz

WORKDIR /home/SVF-tools/mxml-4.0.4

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
RUN mkdir -p ~/bc && \
    extract-bc fuzz_mxml && \
    mv fuzz_mxml.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
