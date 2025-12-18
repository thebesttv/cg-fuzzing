FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract libyaml 0.2.5
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/yaml/libyaml/releases/download/0.2.5/yaml-0.2.5.tar.gz && \
    tar -xzf yaml-0.2.5.tar.gz && \
    rm yaml-0.2.5.tar.gz

WORKDIR /home/SVF-tools/yaml-0.2.5

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
# libyaml uses autotools, configure and make
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

# Build libyaml
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
# run-parser is the CLI tool for parsing YAML files
RUN mkdir -p ~/bc && \
    extract-bc tests/run-parser && \
    mv tests/run-parser.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
