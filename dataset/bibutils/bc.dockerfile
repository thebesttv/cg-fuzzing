FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract bibutils 7.2
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 "https://sourceforge.net/projects/bibutils/files/bibutils_7.2_src.tgz/download" -O bibutils_7.2_src.tgz && \
    tar -xzf bibutils_7.2_src.tgz && \
    rm bibutils_7.2_src.tgz

WORKDIR /home/SVF-tools/bibutils_7.2

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
# Note: bibutils configure doesn't respect CC env var, so we modify after configure
RUN FORCE_UNSAFE_CONFIGURE=1 ./configure --static && \
    sed -i 's|^CC.*=.*|CC = wllvm|' Makefile && \
    sed -i 's|^CFLAGS.*=.*|CFLAGS = -g -O0 -Xclang -disable-llvm-passes|' Makefile

# Build bibutils
RUN LDFLAGS="-static -Wl,--allow-multiple-definition" make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    for dir in bin lib; do \
        if [ -d "$dir" ]; then \
            for bin in "$dir"/*; do \
                if [ -f "$bin" ] && [ -x "$bin" ] && file "$bin" | grep -q "ELF"; then \
                    extract-bc "$bin" && \
                    mv "${bin}.bc" ~/bc/ 2>/dev/null || true; \
                fi; \
            done; \
        fi; \
    done

# Verify that bc files were created
RUN ls -la ~/bc/
