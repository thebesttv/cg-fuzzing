FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y file python3 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract wren 0.4.0
WORKDIR /home/SVF-tools
RUN wget https://github.com/wren-lang/wren/archive/refs/tags/0.4.0.tar.gz && \
    tar -xzf 0.4.0.tar.gz && \
    rm 0.4.0.tar.gz

WORKDIR /home/SVF-tools/wren-0.4.0/projects/make

# Build wren with WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    make config=debug_64bit wren

# Copy the harness
COPY wren/harness.c /home/SVF-tools/wren-0.4.0/harness.c

WORKDIR /home/SVF-tools/wren-0.4.0

# Build the harness
RUN wllvm -g -O0 -Xclang -disable-llvm-passes -I src/include \
    -static -Wl,--allow-multiple-definition \
    harness.c lib/libwren_d.a -lm -o wren_parse

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc wren_parse && \
    mv wren_parse.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
