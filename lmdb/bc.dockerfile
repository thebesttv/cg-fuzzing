FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract lmdb 0.9.31
WORKDIR /home/SVF-tools
RUN wget https://github.com/LMDB/lmdb/archive/refs/tags/LMDB_0.9.31.tar.gz && \
    tar -xzf LMDB_0.9.31.tar.gz && \
    rm LMDB_0.9.31.tar.gz

WORKDIR /home/SVF-tools/lmdb-LMDB_0.9.31/libraries/liblmdb

# Build lmdb with WLLVM for bitcode extraction
# Static linking with mdb_load as target
# Need to explicitly set CC on make command line to override Makefile default
RUN make CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes -pthread" \
    LDFLAGS="-static -Wl,--allow-multiple-definition -pthread" \
    mdb_load mdb_dump mdb_stat mdb_copy -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    for bin in mdb_load mdb_dump mdb_stat mdb_copy; do \
        if [ -f "$bin" ] && [ -x "$bin" ]; then \
            extract-bc "$bin" && \
            mv "${bin}.bc" ~/bc/ 2>/dev/null || true; \
        fi; \
    done

# Verify that bc files were created
RUN ls -la ~/bc/
