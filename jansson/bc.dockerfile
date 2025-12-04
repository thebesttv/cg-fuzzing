FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract jansson 2.14.1
WORKDIR /home/SVF-tools
RUN wget https://github.com/akheron/jansson/releases/download/v2.14.1/jansson-2.14.1.tar.gz && \
    tar -xzf jansson-2.14.1.tar.gz && \
    rm jansson-2.14.1.tar.gz

WORKDIR /home/SVF-tools/jansson-2.14.1

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

# Build jansson library and test programs
RUN make -j$(nproc) && \
    make -C test/bin json_process

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc test/bin/json_process && \
    mv test/bin/json_process.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
