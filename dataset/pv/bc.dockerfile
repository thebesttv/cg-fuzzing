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

# Download and extract pv (Pipe Viewer) 1.9.7

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: pv" > /work/proj && \
    echo "version: 1.9.7" >> /work/proj && \
    echo "source: https://www.ivarch.com/programs/sources/pv-1.9.7.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://www.ivarch.com/programs/sources/pv-1.9.7.tar.gz && \
    tar -xzf pv-1.9.7.tar.gz && \
    mv pv-1.9.7 build && \
    rm pv-1.9.7.tar.gz

WORKDIR /work/build

# Configure with WLLVM and static linking
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

# Build pv
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc pv && \
    mv pv.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
