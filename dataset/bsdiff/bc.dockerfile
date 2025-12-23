FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download bsdiff from GitHub (mendsley's mirror)

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: bsdiff" > /work/proj && \
    echo "version: unknown" >> /work/proj && \
    echo "source: https://github.com/mendsley/bsdiff/archive/refs/heads/master.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/mendsley/bsdiff/archive/refs/heads/master.tar.gz && \
    tar -xzf master.tar.gz && \
    mv master build && \
    rm master.tar.gz

WORKDIR /work/build

# Install build dependencies (file for extract-bc, bzip2 for compression)
RUN apt-get update && \
    apt-get install -y file libbz2-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install autotools for building
RUN apt-get update && \
    apt-get install -y autoconf automake libtool && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Generate configure script
RUN ./autogen.sh

# Configure and build bsdiff with WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes -DBSDIFF_EXECUTABLE -DBSPATCH_EXECUTABLE" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure

RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    for bin in bsdiff bspatch; do \
        if [ -f "$bin" ] && [ -x "$bin" ]; then \
            extract-bc "$bin" && \
            mv "${bin}.bc" /work/bc/ 2>/dev/null || true; \
        fi; \
    done

# Verify that bc files were created
RUN ls -la /work/bc/
