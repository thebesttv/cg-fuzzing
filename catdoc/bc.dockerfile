FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract catdoc 0.95
WORKDIR /home/SVF-tools
RUN wget "http://ftp.wagner.pp.ru/pub/catdoc/catdoc-0.95.tar.gz" && \
    tar -xzf catdoc-0.95.tar.gz && \
    rm catdoc-0.95.tar.gz

WORKDIR /home/SVF-tools/catdoc-0.95

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure

# Build catdoc
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc src/catdoc && \
    mv src/catdoc.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
