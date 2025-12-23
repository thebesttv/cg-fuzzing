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

# Download and extract entr 5.6

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: entr" > /work/proj && \
    echo "version: 5.6" >> /work/proj && \
    echo "source: https://github.com/eradman/entr/archive/refs/tags/5.6.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/eradman/entr/archive/refs/tags/5.6.tar.gz && \
    tar -xzf 5.6.tar.gz && \
    mv 5.6 build && \
    rm 5.6.tar.gz

WORKDIR /work/build

# Configure entr (uses simple configure script)
RUN ./configure

# Build entr with WLLVM and static linking
RUN make CC=wllvm CFLAGS="-g -O0 -Xclang -disable-llvm-passes" LDFLAGS="-static -Wl,--allow-multiple-definition" -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc entr && \
    mv entr.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
