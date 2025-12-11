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

# Download and extract gdbm 1.26
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftpmirror.gnu.org/gnu/gdbm/gdbm-1.26.tar.gz && \
    tar -xzf gdbm-1.26.tar.gz && \
    rm gdbm-1.26.tar.gz

WORKDIR /home/SVF-tools/gdbm-1.26

# Install build dependencies
RUN apt-get update && \
    apt-get install -y libreadline-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --without-readline

# Build gdbm
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    for bin in tools/gdbm_load tools/gdbm_dump tools/gdbmtool; do \
        if [ -f "$bin" ] && [ -x "$bin" ]; then \
            extract-bc "$bin" && \
            name=$(basename "$bin") && \
            mv "${bin}.bc" ~/bc/${name}.bc 2>/dev/null || true; \
        fi; \
    done

# Verify that bc files were created
RUN ls -la ~/bc/
