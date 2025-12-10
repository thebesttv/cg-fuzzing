FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y file zlib1g-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract potrace 1.16
WORKDIR /home/SVF-tools
RUN wget https://potrace.sourceforge.net/download/1.16/potrace-1.16.tar.gz && \
    tar -xzf potrace-1.16.tar.gz && \
    rm potrace-1.16.tar.gz

WORKDIR /home/SVF-tools/potrace-1.16

# Configure and build with WLLVM for bitcode extraction
# potrace uses autotools
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc src/potrace && \
    mv src/potrace.bc ~/bc/ && \
    extract-bc src/mkbitmap && \
    mv src/mkbitmap.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
