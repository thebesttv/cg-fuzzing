FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Copy and extract moreutils 0.69
WORKDIR /home/SVF-tools
COPY moreutils/moreutils-0.69.tar.gz /home/SVF-tools/
RUN tar -xzf moreutils-0.69.tar.gz && \
    rm moreutils-0.69.tar.gz

WORKDIR /home/SVF-tools/moreutils-0.69

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file libxml2-dev libxslt1-dev docbook-xml docbook-xsl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build moreutils with WLLVM (simple Makefile)
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    make -j$(nproc) || true

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    for bin in sponge chronic ts pee; do \
        if [ -f "$bin" ]; then \
            extract-bc "$bin" && \
            mv "${bin}.bc" ~/bc/ 2>/dev/null || true; \
        fi; \
    done

# Verify that bc files were created
RUN ls -la ~/bc/
