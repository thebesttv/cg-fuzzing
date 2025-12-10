FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract coreutils v9.5 (using official release tarball which doesn't require bootstrap)
WORKDIR /home/SVF-tools
RUN apt-get update && \
    apt-get install -y xz-utils file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/coreutils/coreutils-9.5.tar.xz && \
    tar -xf coreutils-9.5.tar.xz && \
    rm coreutils-9.5.tar.xz

WORKDIR /home/SVF-tools/coreutils-9.5

# Configure with static linking and WLLVM
# Disable stdbuf to avoid conflict between static linking and shared library
# Note: --allow-multiple-definition is required for static linking with glibc
RUN CC=wllvm \
    CFLAGS="-g -O0" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-nls --enable-no-install-program=stdbuf

# Build coreutils
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
# Note: Some binaries may fail extract-bc (e.g., if they don't have embedded bitcode), which is expected
RUN mkdir -p ~/bc && \
    for bin in src/*; do \
        if [ -f "$bin" ] && [ -x "$bin" ] && file "$bin" | grep -q "ELF"; then \
            extract-bc "$bin" && \
            mv "${bin}.bc" ~/bc/ 2>/dev/null || true; \
        fi; \
    done

# Verify that bc files were created
RUN ls -la ~/bc/
