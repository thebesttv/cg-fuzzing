FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract jemalloc v5.3.0
WORKDIR /home/SVF-tools
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/jemalloc/jemalloc/releases/download/5.3.0/jemalloc-5.3.0.tar.bz2 && \
    tar -xjf jemalloc-5.3.0.tar.bz2 && \
    rm jemalloc-5.3.0.tar.bz2

WORKDIR /home/SVF-tools/jemalloc-5.3.0

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file autoconf && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
# jemalloc uses autoconf, disable shared libs to avoid PIC issues
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared --enable-static

# Build jemalloc library (skip shared libs) and tests
RUN make build_lib_static -j$(nproc) && \
    make tests -j$(nproc)

# Create bc directory and extract bitcode files from test binaries
RUN mkdir -p ~/bc && \
    for bin in test/unit/* test/integration/* test/integration/cpp/* test/stress/*; do \
        if [ -f "$bin" ] && [ -x "$bin" ] && file "$bin" | grep -q "ELF"; then \
            extract-bc "$bin" && \
            basename_bc=$(basename "$bin").bc && \
            mv "${bin}.bc" ~/bc/"${basename_bc}" 2>/dev/null || true; \
        fi; \
    done

# Verify that bc files were created
RUN ls -la ~/bc/
