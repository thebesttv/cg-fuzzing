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

# Download and extract lmdb 0.9.31

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: lmdb" > /work/proj && \
    echo "version: 0.9.31" >> /work/proj && \
    echo "source: https://github.com/LMDB/lmdb/archive/refs/tags/LMDB_0.9.31.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/LMDB/lmdb/archive/refs/tags/LMDB_0.9.31.tar.gz && \
    tar -xzf LMDB_0.9.31.tar.gz && \
    mv LMDB_0.9.31 build && \
    rm LMDB_0.9.31.tar.gz

WORKDIR /work/build

# Build lmdb with WLLVM for bitcode extraction
# Static linking with mdb_load as target
# Need to explicitly set CC on make command line to override Makefile default
RUN make CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes -pthread" \
    LDFLAGS="-static -Wl,--allow-multiple-definition -pthread" \
    mdb_load mdb_dump mdb_stat mdb_copy -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    for bin in mdb_load mdb_dump mdb_stat mdb_copy; do \
        if [ -f "$bin" ] && [ -x "$bin" ]; then \
            extract-bc "$bin" && \
            mv "${bin}.bc" /work/bc/ 2>/dev/null || true; \
        fi; \
    done

# Verify that bc files were created
RUN ls -la /work/bc/
