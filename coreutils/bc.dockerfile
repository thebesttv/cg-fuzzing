FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract coreutils v9.9
WORKDIR /home/SVF-tools
RUN wget https://github.com/coreutils/coreutils/archive/refs/tags/v9.9.tar.gz && \
    tar -xzf v9.9.tar.gz && \
    rm v9.9.tar.gz

WORKDIR /home/SVF-tools/coreutils-9.9

# Install build dependencies (including git for bootstrap, file for extract-bc)
RUN apt-get update && \
    apt-get install -y autoconf automake autopoint bison gettext gperf texinfo git rsync file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Initialize git for bootstrap and fetch gnulib
RUN git init && \
    git config user.email "build@example.com" && \
    git config user.name "Build" && \
    git add -A && git commit -m "init"

# Get gnulib submodule
RUN git clone --depth 1 https://github.com/coreutils/gnulib.git gnulib

# Bootstrap the build system
RUN ./bootstrap --skip-po --gnulib-srcdir=gnulib

# Configure with static linking and WLLVM
# Disable stdbuf to avoid conflict between static linking and shared library
# Note: --allow-multiple-definition is required for static linking with glibc
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
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
