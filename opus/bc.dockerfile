FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y autoconf automake libtool file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract opus v1.5.2
WORKDIR /home/SVF-tools
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/xiph/opus/releases/download/v1.5.2/opus-1.5.2.tar.gz && \
    tar -xzf opus-1.5.2.tar.gz && \
    rm opus-1.5.2.tar.gz

WORKDIR /home/SVF-tools/opus-1.5.2

# Configure with static linking and WLLVM
# Enable all optional features for better fuzzing coverage
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --disable-doc

# Build opus library and demo tools
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc opus_demo && \
    mv opus_demo.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
