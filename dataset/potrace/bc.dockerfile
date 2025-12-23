FROM thebesttv/svf:latest

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

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: potrace" > /work/proj && \
    echo "version: 1.16" >> /work/proj && \
    echo "source: https://potrace.sourceforge.net/download/1.16/potrace-1.16.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://potrace.sourceforge.net/download/1.16/potrace-1.16.tar.gz && \
    tar -xzf potrace-1.16.tar.gz && \
    mv potrace-1.16 build && \
    rm potrace-1.16.tar.gz

WORKDIR /work/build

# Configure and build with WLLVM for bitcode extraction
# potrace uses autotools
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc src/potrace && \
    mv src/potrace.bc /work/bc/ && \
    extract-bc src/mkbitmap && \
    mv src/mkbitmap.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
