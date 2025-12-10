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

# Download and extract RHash 1.4.5
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/rhash/RHash/archive/refs/tags/v1.4.5.tar.gz && \
    tar -xzf v1.4.5.tar.gz && \
    rm v1.4.5.tar.gz

WORKDIR /home/SVF-tools/RHash-1.4.5

# Configure RHash - disable shared library, use static linking, no openssl
RUN ./configure --cc=wllvm --extra-cflags="-g -O0 -Xclang -disable-llvm-passes" --extra-ldflags="-static -Wl,--allow-multiple-definition" --disable-lib-shared --enable-static --disable-openssl --disable-openssl-runtime

# Build RHash
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc rhash && \
    mv rhash.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
