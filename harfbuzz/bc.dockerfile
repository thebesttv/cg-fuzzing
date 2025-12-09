FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract harfbuzz v12.2.0
WORKDIR /home/SVF-tools
RUN wget https://github.com/harfbuzz/harfbuzz/releases/download/12.2.0/harfbuzz-12.2.0.tar.xz && \
    tar -xf harfbuzz-12.2.0.tar.xz && \
    rm harfbuzz-12.2.0.tar.xz

WORKDIR /home/SVF-tools/harfbuzz-12.2.0

# Install build dependencies (file for extract-bc, meson/ninja, pkg-config)
RUN apt-get update && \
    apt-get install -y file meson ninja-build pkg-config && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with meson and static linking using WLLVM
RUN CC=wllvm \
    CXX=wllvm++ \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    CXXFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    meson setup build \
        --default-library=static \
        --prefer-static \
        -Dtests=disabled \
        -Ddocs=disabled \
        -Dbenchmark=disabled \
        -Dintrospection=disabled \
        -Dglib=disabled \
        -Dgobject=disabled \
        -Dicu=disabled \
        -Dfreetype=disabled \
        -Dcairo=disabled

# Build harfbuzz
RUN ninja -C build

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    for bin in build/util/hb-*; do \
        if [ -f "$bin" ] && [ -x "$bin" ] && file "$bin" | grep -q "ELF"; then \
            extract-bc "$bin" && \
            mv "${bin}.bc" ~/bc/ 2>/dev/null || true; \
        fi; \
    done

# Verify that bc files were created
RUN ls -la ~/bc/
