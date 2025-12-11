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

# Download and extract pv (Pipe Viewer) 1.9.7
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://www.ivarch.com/programs/sources/pv-1.9.7.tar.gz && \
    tar -xzf pv-1.9.7.tar.gz && \
    rm pv-1.9.7.tar.gz

WORKDIR /home/SVF-tools/pv-1.9.7

# Configure with WLLVM and static linking
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

# Build pv
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc pv && \
    mv pv.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
